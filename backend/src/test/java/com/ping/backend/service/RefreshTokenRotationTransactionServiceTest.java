
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.dto.auth.RefreshTokenRotationOutcome;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenRotationTransactionServiceTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private static final UUID SESSION_ID = UUID.randomUUID();

    private static final UUID TOKEN_ID = UUID.randomUUID();

    private static final String TOKEN_HASH = "a".repeat(64);

    private static final String REPLACEMENT_RAW_TOKEN =
            "B".repeat(42) + "A";

    private static final String REPLACEMENT_TOKEN_HASH =
            "b".repeat(64);

    private static final Instant CREATED_AT =
            Instant.parse("2026-01-01T00:00:00Z");

    private static final Instant CURRENT_TIME =
            Instant.parse("2026-01-11T00:00:00Z");

    private static final Duration REFRESH_TOKEN_TTL =
            Duration.ofDays(30);

    private static final Duration SESSION_TTL =
            Duration.ofDays(90);

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenGenerator refreshTokenGenerator;

    private RefreshTokenRotationTransactionService transactionService;

    private AuthSession session;

    private RefreshToken currentToken;

    @BeforeEach
    void setUp() {
        session = new AuthSession(
                SESSION_ID,
                USER_ID,
                CREATED_AT,
                CREATED_AT.plus(SESSION_TTL)
        );

        currentToken = new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                CREATED_AT.plus(REFRESH_TOKEN_TTL)
        );

        transactionService = createTransactionService(CURRENT_TIME);
    }


    private void assertRejectedWithoutMutation(
            RefreshTokenRotationOutcome outcome
    ) {
        assertThat(outcome.status())
                .isEqualTo(
                        RefreshTokenRotationOutcome.Status.REJECTED
                );

        assertThat(outcome.isSuccess()).isFalse();

        assertThat(outcome.result()).isNull();

        assertThat(currentToken.getConsumedAt()).isNull();

        verifyNoInteractions(refreshTokenGenerator);

        verify(refreshTokenRepository, never()).flush();

        verify(refreshTokenRepository, never())
                .saveAndFlush(any(RefreshToken.class));

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }

    private void assertConsumedTokenOutcome(
            RefreshTokenRotationOutcome outcome,
            RefreshTokenRotationOutcome.Status expectedStatus,
            Instant originalConsumedAt,
            Instant expectedRevokedAt
    ) {
        assertThat(outcome.status())
                .isEqualTo(expectedStatus);

        assertThat(outcome.isSuccess()).isFalse();

        assertThat(outcome.result()).isNull();

        assertThat(currentToken.isConsumed()).isTrue();

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(originalConsumedAt);

        assertThat(session.getRevokedAt())
                .isEqualTo(expectedRevokedAt);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        verifyNoInteractions(refreshTokenGenerator);

        verifyNoMoreInteractions(
                refreshTokenRepository,
                authSessionRepository
        );
    }


    private RefreshTokenRotationTransactionService
    createTransactionService(Instant now) {
        return new RefreshTokenRotationTransactionService(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator,
                new AuthProperties(
                        REFRESH_TOKEN_TTL,
                        SESSION_TTL
                ),
                Clock.fixed(now, ZoneOffset.UTC)
        );
    }

    private void stubTokenLookup() {
        when(refreshTokenRepository
                .findSessionIdByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(SESSION_ID));

        when(authSessionRepository
                .findByIdForUpdate(SESSION_ID))
                .thenReturn(Optional.of(session));

        when(refreshTokenRepository
                .findByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(currentToken));
    }

    private void stubReplacementGeneration() {
        when(refreshTokenGenerator.generate())
                .thenReturn(REPLACEMENT_RAW_TOKEN);

        when(refreshTokenGenerator.hash(REPLACEMENT_RAW_TOKEN))
                .thenReturn(REPLACEMENT_TOKEN_HASH);
    }

    private RefreshToken captureReplacementToken() {
        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        verify(refreshTokenRepository)
                .saveAndFlush(captor.capture());

        return captor.getValue();
    }

    @Test
    void rotate_whenTokenIsValid_consumesOldTokenAndCreatesReplacement() {
        stubTokenLookup();
        stubReplacementGeneration();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.status())
                .isEqualTo(
                        RefreshTokenRotationOutcome.Status.SUCCESS
                );

        assertThat(outcome.isSuccess()).isTrue();

        RefreshTokenRotationResult result = outcome.result();

        assertThat(result).isNotNull();

        assertThat(result.userId()).isEqualTo(USER_ID);

        assertThat(result.sessionId()).isEqualTo(SESSION_ID);

        assertThat(result.rawRefreshToken())
                .isEqualTo(REPLACEMENT_RAW_TOKEN);

        assertThat(result.refreshTokenExpiresAt())
                .isEqualTo(CURRENT_TIME.plus(REFRESH_TOKEN_TTL));

        assertThat(result.sessionExpiresAt())
                .isEqualTo(CREATED_AT.plus(SESSION_TTL));

        assertThat(currentToken.isConsumed()).isTrue();

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(CURRENT_TIME);

        assertThat(session.isRevoked()).isFalse();

        assertThat(session.getExpiresAt())
                .isEqualTo(CREATED_AT.plus(SESSION_TTL));

        RefreshToken replacementToken =
                captureReplacementToken();

        assertThat(replacementToken.getId())
                .isNotNull()
                .isNotEqualTo(TOKEN_ID);

        assertThat(replacementToken.getSessionId())
                .isEqualTo(SESSION_ID);

        assertThat(replacementToken.getTokenHash())
                .isEqualTo(REPLACEMENT_TOKEN_HASH)
                .isNotEqualTo(REPLACEMENT_RAW_TOKEN)
                .isNotEqualTo(TOKEN_HASH);

        assertThat(replacementToken.getCreatedAt())
                .isEqualTo(CURRENT_TIME);

        assertThat(replacementToken.getExpiresAt())
                .isEqualTo(result.refreshTokenExpiresAt());

        assertThat(replacementToken.getConsumedAt()).isNull();
    }

    @Test
    void rotate_whenRefreshTtlExceedsRemainingSession_capsExpiration() {
        Instant rotationTime =
                CREATED_AT.plus(Duration.ofDays(75));

        Instant sessionExpiration =
                CREATED_AT.plus(SESSION_TTL);

        Instant tokenCreation =
                CREATED_AT.plus(Duration.ofDays(60));

        currentToken = new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                tokenCreation,
                sessionExpiration
        );

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();
        stubReplacementGeneration();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.isSuccess()).isTrue();

        assertThat(outcome.result().refreshTokenExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(outcome.result().sessionExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(rotationTime);

        RefreshToken replacementToken =
                captureReplacementToken();

        assertThat(replacementToken.getCreatedAt())
                .isEqualTo(rotationTime);

        assertThat(replacementToken.getExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(Duration.between(
                replacementToken.getCreatedAt(),
                replacementToken.getExpiresAt()
        )).isEqualTo(Duration.ofDays(15));

        assertThat(session.getExpiresAt())
                .isEqualTo(sessionExpiration);
    }

    @Test
    void rotate_whenSuccessful_executesOperationsInCorrectOrder() {
        stubTokenLookup();
        stubReplacementGeneration();

        doAnswer(invocation -> {
            assertThat(currentToken.isConsumed()).isTrue();

            assertThat(currentToken.getConsumedAt())
                    .isEqualTo(CURRENT_TIME);

            return null;
        }).when(refreshTokenRepository).flush();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.isSuccess()).isTrue();

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        inOrder.verify(refreshTokenGenerator)
                .generate();

        inOrder.verify(refreshTokenGenerator)
                .hash(REPLACEMENT_RAW_TOKEN);

        inOrder.verify(refreshTokenRepository)
                .flush();

        inOrder.verify(refreshTokenRepository)
                .saveAndFlush(any(RefreshToken.class));

        verifyNoMoreInteractions(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );
    }

    @Test
    void rotate_whenClockHasNanosecondPrecision_truncatesToMicroseconds() {
        Instant preciseTime =
                Instant.parse(
                        "2026-01-11T00:00:00.123456789Z"
                );

        Instant expectedTime =
                preciseTime.truncatedTo(ChronoUnit.MICROS);

        transactionService =
                createTransactionService(preciseTime);

        stubTokenLookup();
        stubReplacementGeneration();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.isSuccess()).isTrue();

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(expectedTime);

        RefreshToken replacementToken =
                captureReplacementToken();

        assertThat(replacementToken.getCreatedAt())
                .isEqualTo(expectedTime);

        assertThat(replacementToken.getExpiresAt())
                .isEqualTo(expectedTime.plus(REFRESH_TOKEN_TTL));

        assertThat(outcome.result().refreshTokenExpiresAt())
                .isEqualTo(replacementToken.getExpiresAt());
    }


    @Test
    void rotate_whenTokenHashIsUnknown_rejectsWithoutLocking() {
        when(refreshTokenRepository
                .findSessionIdByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.empty());

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        verifyNoInteractions(authSessionRepository);

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @Test
    void rotate_whenSessionIsNotFound_rejectsWithoutLoadingToken() {
        when(refreshTokenRepository
                .findSessionIdByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(SESSION_ID));

        when(authSessionRepository
                .findByIdForUpdate(SESSION_ID))
                .thenReturn(Optional.empty());

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @Test
    void rotate_whenTokenIsNotFoundAfterLocking_rejectsRequest() {
        when(refreshTokenRepository
                .findSessionIdByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(SESSION_ID));

        when(authSessionRepository
                .findByIdForUpdate(SESSION_ID))
                .thenReturn(Optional.of(session));

        when(refreshTokenRepository
                .findByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.empty());

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @Test
    void rotate_whenTokenBelongsToDifferentSession_rejectsRequest() {
        UUID differentSessionId = UUID.randomUUID();

        currentToken = new RefreshToken(
                TOKEN_ID,
                differentSessionId,
                TOKEN_HASH,
                CREATED_AT,
                CREATED_AT.plus(REFRESH_TOKEN_TTL)
        );

        stubTokenLookup();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @Test
    void rotate_whenSessionIsAlreadyRevoked_preservesRevocationTimestamp() {
        Instant originalRevokedAt =
                CURRENT_TIME.minus(Duration.ofDays(1));

        session.revoke(originalRevokedAt);

        stubTokenLookup();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        assertThat(session.isRevoked()).isTrue();

        assertThat(session.getRevokedAt())
                .isEqualTo(originalRevokedAt);

        assertRejectedWithoutMutation(outcome);
    }


    @ParameterizedTest
    @ValueSource(longs = {0, 1})
    void rotate_whenSessionHasExpired_rejectsRequest(
            long microsecondsAfterExpiration
    ) {
        Instant sessionExpiration =
                CREATED_AT.plus(SESSION_TTL);

        Instant rotationTime = sessionExpiration.plus(
                microsecondsAfterExpiration,
                ChronoUnit.MICROS
        );

        currentToken = new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                sessionExpiration.minus(Duration.ofDays(10)),
                sessionExpiration
        );

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        assertThat(session.isExpired(rotationTime)).isTrue();

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @ParameterizedTest
    @ValueSource(longs = {0, 1})
    void rotate_whenUnconsumedTokenHasExpired_rejectsRequest(
            long microsecondsAfterExpiration
    ) {
        Instant tokenExpiration =
                currentToken.getExpiresAt();

        Instant rotationTime = tokenExpiration.plus(
                microsecondsAfterExpiration,
                ChronoUnit.MICROS
        );

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        assertThat(session.isActive(rotationTime)).isTrue();

        assertThat(currentToken.isExpired(rotationTime)).isTrue();

        assertThat(session.getRevokedAt()).isNull();

        assertRejectedWithoutMutation(outcome);
    }


    @Test
    void rotate_whenTokenExpiresOneMicrosecondLater_allowsRotation() {
        Instant rotationTime = currentToken.getExpiresAt()
                .minus(1, ChronoUnit.MICROS);

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();
        stubReplacementGeneration();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.isSuccess()).isTrue();

        assertThat(currentToken.isExpired(rotationTime))
                .isFalse();

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(rotationTime);

        assertThat(session.getRevokedAt()).isNull();

        RefreshToken replacementToken =
                captureReplacementToken();

        assertThat(replacementToken.getCreatedAt())
                .isEqualTo(rotationTime);

        assertThat(replacementToken.getExpiresAt())
                .isEqualTo(
                        rotationTime.plus(REFRESH_TOKEN_TTL)
                );

        assertThat(outcome.result().refreshTokenExpiresAt())
                .isEqualTo(replacementToken.getExpiresAt());

        assertThat(replacementToken.getConsumedAt()).isNull();
    }


    @Test
    void rotate_whenSessionExpiresOneMicrosecondLater_capsReplacementLifetime() {
        Instant sessionExpiration =
                session.getExpiresAt();

        Instant rotationTime = sessionExpiration
                .minus(1, ChronoUnit.MICROS);

        currentToken = new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                sessionExpiration.minus(REFRESH_TOKEN_TTL),
                sessionExpiration
        );

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();
        stubReplacementGeneration();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(outcome.isSuccess()).isTrue();

        assertThat(session.isActive(rotationTime)).isTrue();

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(rotationTime);

        assertThat(session.getRevokedAt()).isNull();

        RefreshToken replacementToken =
                captureReplacementToken();

        assertThat(replacementToken.getCreatedAt())
                .isEqualTo(rotationTime);

        assertThat(replacementToken.getExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(Duration.between(
                replacementToken.getCreatedAt(),
                replacementToken.getExpiresAt()
        )).isEqualTo(Duration.ofNanos(1_000));

        assertThat(outcome.result().refreshTokenExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(outcome.result().sessionExpiresAt())
                .isEqualTo(sessionExpiration);
    }


    @Test
    void rotate_whenConsumedTokenIsReused_revokesActiveSession() {
        Instant originalConsumedAt =
                CURRENT_TIME.minus(Duration.ofDays(1));

        currentToken.consume(originalConsumedAt);

        stubTokenLookup();

        assertThat(session.isActive(CURRENT_TIME)).isTrue();

        assertThat(currentToken.isExpired(CURRENT_TIME))
                .isFalse();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(session.isRevoked()).isTrue();

        assertThat(session.isActive(CURRENT_TIME))
                .isFalse();

        assertThat(session.getExpiresAt())
                .isEqualTo(CREATED_AT.plus(SESSION_TTL));

        assertConsumedTokenOutcome(
                outcome,
                RefreshTokenRotationOutcome.Status.REUSE_DETECTED,
                originalConsumedAt,
                CURRENT_TIME
        );
    }


    @Test
    void rotate_whenExpiredConsumedTokenIsReused_revokesActiveSession() {
        Instant originalConsumedAt =
                CREATED_AT.plus(Duration.ofDays(10));

        currentToken.consume(originalConsumedAt);

        Instant rotationTime =
                CREATED_AT.plus(Duration.ofDays(35));

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();

        assertThat(session.isActive(rotationTime)).isTrue();

        assertThat(currentToken.isConsumed()).isTrue();

        assertThat(currentToken.isExpired(rotationTime))
                .isTrue();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(session.isRevoked()).isTrue();

        assertConsumedTokenOutcome(
                outcome,
                RefreshTokenRotationOutcome.Status.REUSE_DETECTED,
                originalConsumedAt,
                rotationTime
        );
    }


    @Test
    void rotate_whenConsumedTokenBelongsToExpiredSession_rejectsWithoutRevoking() {
        Instant originalConsumedAt =
                CREATED_AT.plus(Duration.ofDays(10));

        currentToken.consume(originalConsumedAt);

        Instant rotationTime = session.getExpiresAt();

        transactionService =
                createTransactionService(rotationTime);

        stubTokenLookup();

        assertThat(session.isExpired(rotationTime)).isTrue();

        assertThat(currentToken.isConsumed()).isTrue();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertThat(session.isRevoked()).isFalse();

        assertConsumedTokenOutcome(
                outcome,
                RefreshTokenRotationOutcome.Status.REJECTED,
                originalConsumedAt,
                null
        );
    }


    @Test
    void rotate_whenConsumedTokenBelongsToRevokedSession_preservesRevocation() {
        Instant originalConsumedAt =
                CREATED_AT.plus(Duration.ofDays(5));

        Instant originalRevokedAt =
                CREATED_AT.plus(Duration.ofDays(8));

        currentToken.consume(originalConsumedAt);

        session.revoke(originalRevokedAt);

        stubTokenLookup();

        assertThat(session.isRevoked()).isTrue();

        assertThat(currentToken.isExpired(CURRENT_TIME))
                .isFalse();

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(TOKEN_HASH);

        assertConsumedTokenOutcome(
                outcome,
                RefreshTokenRotationOutcome.Status.REJECTED,
                originalConsumedAt,
                originalRevokedAt
        );
    }


    @Test
    void rotate_whenTokenHashIsNull_throwsExceptionWithoutInteractions() {
        assertThatThrownBy(() ->
                transactionService.rotate(null)
        )
                .isInstanceOf(NullPointerException.class)
                .hasMessage("tokenHash is required");

        verifyNoInteractions(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator
        );

        assertThat(currentToken.getConsumedAt()).isNull();

        assertThat(session.getRevokedAt()).isNull();
    }


    @Test
    void rotate_whenSessionLockFails_propagatesException() {
        CannotAcquireLockException failure =
                new CannotAcquireLockException(
                        "Simulated session locking failure"
                );

        when(refreshTokenRepository
                .findSessionIdByTokenHash(TOKEN_HASH))
                .thenReturn(Optional.of(SESSION_ID));

        when(authSessionRepository
                .findByIdForUpdate(SESSION_ID))
                .thenThrow(failure);

        assertThatThrownBy(() ->
                transactionService.rotate(TOKEN_HASH)
        ).isSameAs(failure);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        assertThat(currentToken.getConsumedAt()).isNull();

        assertThat(session.getRevokedAt()).isNull();

        verifyNoInteractions(refreshTokenGenerator);

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }


    @Test
    void rotate_whenReplacementGenerationFails_doesNotConsumeCurrentToken() {
        stubTokenLookup();

        IllegalStateException failure =
                new IllegalStateException(
                        "Simulated token generation failure"
                );

        when(refreshTokenGenerator.generate())
                .thenThrow(failure);

        assertThatThrownBy(() ->
                transactionService.rotate(TOKEN_HASH)
        ).isSameAs(failure);

        assertThat(currentToken.getConsumedAt()).isNull();

        assertThat(session.getRevokedAt()).isNull();

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        inOrder.verify(refreshTokenGenerator).generate();

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator
        );
    }


    @Test
    void rotate_whenReplacementHashingFails_doesNotConsumeCurrentToken() {
        stubTokenLookup();

        IllegalStateException failure =
                new IllegalStateException(
                        "Simulated replacement hashing failure"
                );

        when(refreshTokenGenerator.generate())
                .thenReturn(REPLACEMENT_RAW_TOKEN);

        when(refreshTokenGenerator.hash(REPLACEMENT_RAW_TOKEN))
                .thenThrow(failure);

        assertThatThrownBy(() ->
                transactionService.rotate(TOKEN_HASH)
        ).isSameAs(failure);

        assertThat(currentToken.getConsumedAt()).isNull();

        assertThat(session.getRevokedAt()).isNull();

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        inOrder.verify(refreshTokenGenerator).generate();

        inOrder.verify(refreshTokenGenerator)
                .hash(REPLACEMENT_RAW_TOKEN);

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator
        );
    }


    @Test
    void rotate_whenConsumptionFlushFails_doesNotPersistReplacement() {
        stubTokenLookup();
        stubReplacementGeneration();

        DataIntegrityViolationException failure =
                new DataIntegrityViolationException(
                        "Simulated consumption flush failure"
                );

        doThrow(failure)
                .when(refreshTokenRepository)
                .flush();

        assertThatThrownBy(() ->
                transactionService.rotate(TOKEN_HASH)
        ).isSameAs(failure);

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(CURRENT_TIME);

        assertThat(session.getRevokedAt()).isNull();

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        inOrder.verify(refreshTokenGenerator).generate();

        inOrder.verify(refreshTokenGenerator)
                .hash(REPLACEMENT_RAW_TOKEN);

        inOrder.verify(refreshTokenRepository).flush();

        verify(refreshTokenRepository, never())
                .saveAndFlush(any(RefreshToken.class));

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator
        );
    }


    @Test
    void rotate_whenReplacementPersistenceFails_propagatesException() {
        stubTokenLookup();
        stubReplacementGeneration();

        DataIntegrityViolationException failure =
                new DataIntegrityViolationException(
                        "Simulated replacement persistence failure"
                );

        when(refreshTokenRepository
                .saveAndFlush(any(RefreshToken.class)))
                .thenThrow(failure);

        assertThatThrownBy(() ->
                transactionService.rotate(TOKEN_HASH)
        ).isSameAs(failure);

        assertThat(currentToken.getConsumedAt())
                .isEqualTo(CURRENT_TIME);

        assertThat(session.getRevokedAt()).isNull();

        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        InOrder inOrder = inOrder(
                refreshTokenRepository,
                authSessionRepository,
                refreshTokenGenerator
        );

        inOrder.verify(refreshTokenRepository)
                .findSessionIdByTokenHash(TOKEN_HASH);

        inOrder.verify(authSessionRepository)
                .findByIdForUpdate(SESSION_ID);

        inOrder.verify(refreshTokenRepository)
                .findByTokenHash(TOKEN_HASH);

        inOrder.verify(refreshTokenGenerator).generate();

        inOrder.verify(refreshTokenGenerator)
                .hash(REPLACEMENT_RAW_TOKEN);

        inOrder.verify(refreshTokenRepository).flush();

        inOrder.verify(refreshTokenRepository)
                .saveAndFlush(captor.capture());

        RefreshToken replacementToken = captor.getValue();

        assertThat(replacementToken.getSessionId())
                .isEqualTo(SESSION_ID);

        assertThat(replacementToken.getTokenHash())
                .isEqualTo(REPLACEMENT_TOKEN_HASH);

        assertThat(replacementToken.getConsumedAt()).isNull();

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator
        );
    }




}
