
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;

import static org.mockito.Mockito.any;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.never;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenIssuanceServiceTest {

    @Mock
    private AuthSessionRepository authSessionRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private RefreshTokenGenerator refreshTokenGenerator;


    private AuthSession captureSession() {
        ArgumentCaptor<AuthSession> captor =
                ArgumentCaptor.forClass(AuthSession.class);

        verify(authSessionRepository)
                .saveAndFlush(captor.capture());

        return captor.getValue();
    }

    private RefreshToken captureRefreshToken() {
        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        verify(refreshTokenRepository)
                .saveAndFlush(captor.capture());

        return captor.getValue();
    }


    private static final Instant CURRENT_TIME =
            Instant.parse("2026-01-01T00:00:00.123456789Z");

    private static final Instant EXPECTED_CREATED_AT =
            Instant.parse("2026-01-01T00:00:00.123456Z");

    private static final Duration REFRESH_TOKEN_TTL =
            Duration.ofDays(30);

    private static final Duration SESSION_TTL =
            Duration.ofDays(90);

    private final UUID userId = UUID.randomUUID();

    private final String rawRefreshToken = "A".repeat(43);

    private final String tokenHash = "a".repeat(64);

    private final Clock clock = Clock.fixed(
            CURRENT_TIME,
            ZoneOffset.UTC
    );

    private final AuthProperties authProperties =
            new AuthProperties(
                    REFRESH_TOKEN_TTL,
                    SESSION_TTL
            );

    private RefreshTokenIssuanceService issuanceService;

    @BeforeEach
    void setUp() {
        issuanceService = new RefreshTokenIssuanceService(
                authSessionRepository,
                refreshTokenRepository,
                refreshTokenGenerator,
                authProperties,
                clock
        );
    }

    private void mockSuccessfulTokenGeneration() {
        when(refreshTokenGenerator.generate())
                .thenReturn(rawRefreshToken);

        when(refreshTokenGenerator.hash(rawRefreshToken))
                .thenReturn(tokenHash);
    }


    @Test
    void issue_withNullUserId_throwsNullPointerException() {
        assertThatThrownBy(() -> issuanceService.issue(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("userId is required");
    }


    @Test
    void issue_withNullUserId_doesNotInteractWithDependencies() {
        assertThatThrownBy(() -> issuanceService.issue(null))
                .isInstanceOf(NullPointerException.class);

        verifyNoInteractions(
                refreshTokenGenerator,
                authSessionRepository,
                refreshTokenRepository
        );
    }


    @Test
    void issue_withValidUserId_returnsIssuanceResult() {
        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        AuthSession session = captureSession();

        assertThat(result).isNotNull();
        assertThat(result.rawRefreshToken())
                .isEqualTo(rawRefreshToken);
        assertThat(result.sessionId())
                .isEqualTo(session.getId());
        assertThat(result.refreshTokenExpiresAt())
                .isEqualTo(EXPECTED_CREATED_AT.plus(REFRESH_TOKEN_TTL));
        assertThat(result.sessionExpiresAt())
                .isEqualTo(EXPECTED_CREATED_AT.plus(SESSION_TTL));
    }


    @Test
    void issue_withValidUserId_createsSessionForUser() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();

        assertThat(session.getUserId())
                .isEqualTo(userId);

        assertThat(session.getId()).isNotNull();
    }


    @Test
    void issue_createsSessionWithCorrectTimestamps() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();

        assertThat(session.getCreatedAt())
                .isEqualTo(EXPECTED_CREATED_AT);

        assertThat(session.getExpiresAt())
                .isEqualTo(EXPECTED_CREATED_AT.plus(SESSION_TTL));
    }


    @Test
    void issue_createsActiveSession() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();

        assertThat(session.getRevokedAt()).isNull();

        assertThat(session.isRevoked()).isFalse();

        assertThat(session.isActive(EXPECTED_CREATED_AT))
                .isTrue();
    }


    @Test
    void issue_createsRefreshTokenLinkedToSession() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        assertThat(refreshToken.getSessionId())
                .isEqualTo(session.getId());
    }


    @Test
    void issue_persistsHashedRefreshToken() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        RefreshToken refreshToken = captureRefreshToken();

        assertThat(refreshToken.getTokenHash())
                .isEqualTo(tokenHash)
                .isNotEqualTo(rawRefreshToken)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }


    @Test
    void issue_createsRefreshTokenWithCorrectTimestamps() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        RefreshToken refreshToken = captureRefreshToken();

        assertThat(refreshToken.getCreatedAt())
                .isEqualTo(EXPECTED_CREATED_AT);

        assertThat(refreshToken.getExpiresAt())
                .isEqualTo(
                        EXPECTED_CREATED_AT.plus(REFRESH_TOKEN_TTL)
                );
    }


    @Test
    void issue_createsUnconsumedRefreshToken() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        RefreshToken refreshToken = captureRefreshToken();

        assertThat(refreshToken.getConsumedAt()).isNull();

        assertThat(refreshToken.isConsumed()).isFalse();

        assertThat(refreshToken.isExpired(EXPECTED_CREATED_AT))
                .isFalse();
    }


    @Test
    void issue_createsIndependentEntityIds() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        assertThat(session.getId()).isNotNull();

        assertThat(refreshToken.getId())
                .isNotNull()
                .isNotEqualTo(session.getId());
    }


    @Test
    void issue_calledMultipleTimes_createsSeparateSessions() {
        String secondRawToken = "B".repeat(42) + "A";
        String secondTokenHash = "b".repeat(64);

        when(refreshTokenGenerator.generate())
                .thenReturn(rawRefreshToken, secondRawToken);

        when(refreshTokenGenerator.hash(rawRefreshToken))
                .thenReturn(tokenHash);

        when(refreshTokenGenerator.hash(secondRawToken))
                .thenReturn(secondTokenHash);

        RefreshTokenIssuanceResult firstResult =
                issuanceService.issue(userId);

        RefreshTokenIssuanceResult secondResult =
                issuanceService.issue(userId);

        ArgumentCaptor<AuthSession> sessionCaptor =
                ArgumentCaptor.forClass(AuthSession.class);

        ArgumentCaptor<RefreshToken> tokenCaptor =
                ArgumentCaptor.forClass(RefreshToken.class);

        verify(authSessionRepository, times(2))
                .saveAndFlush(sessionCaptor.capture());

        verify(refreshTokenRepository, times(2))
                .saveAndFlush(tokenCaptor.capture());

        AuthSession firstSession =
                sessionCaptor.getAllValues().get(0);

        AuthSession secondSession =
                sessionCaptor.getAllValues().get(1);

        RefreshToken firstToken =
                tokenCaptor.getAllValues().get(0);

        RefreshToken secondToken =
                tokenCaptor.getAllValues().get(1);

        assertThat(firstSession.getId())
                .isNotEqualTo(secondSession.getId());

        assertThat(firstSession.getUserId()).isEqualTo(userId);
        assertThat(secondSession.getUserId()).isEqualTo(userId);

        assertThat(firstToken.getId())
                .isNotEqualTo(secondToken.getId());

        assertThat(firstToken.getSessionId())
                .isEqualTo(firstSession.getId());

        assertThat(secondToken.getSessionId())
                .isEqualTo(secondSession.getId());

        assertThat(firstToken.getTokenHash())
                .isEqualTo(tokenHash);

        assertThat(secondToken.getTokenHash())
                .isEqualTo(secondTokenHash);

        assertThat(firstResult.sessionId())
                .isEqualTo(firstSession.getId());

        assertThat(secondResult.sessionId())
                .isEqualTo(secondSession.getId());

        assertThat(firstResult.rawRefreshToken())
                .isEqualTo(rawRefreshToken);

        assertThat(secondResult.rawRefreshToken())
                .isEqualTo(secondRawToken);
    }


    @Test
    void issue_usesInjectedClock() {
        Instant customTime =
                Instant.parse("2030-06-15T10:30:00Z");

        Clock customClock = Clock.fixed(
                customTime,
                ZoneOffset.UTC
        );

        RefreshTokenIssuanceService customService =
                new RefreshTokenIssuanceService(
                        authSessionRepository,
                        refreshTokenRepository,
                        refreshTokenGenerator,
                        authProperties,
                        customClock
                );

        mockSuccessfulTokenGeneration();

        customService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        assertThat(session.getCreatedAt())
                .isEqualTo(customTime);

        assertThat(refreshToken.getCreatedAt())
                .isEqualTo(customTime);
    }


    @Test
    void issue_normalizesTimestampsToMicroseconds() {
        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        assertThat(session.getCreatedAt())
                .isEqualTo(EXPECTED_CREATED_AT)
                .isNotEqualTo(CURRENT_TIME);

        assertThat(refreshToken.getCreatedAt())
                .isEqualTo(EXPECTED_CREATED_AT);

        assertThat(session.getExpiresAt().getNano() % 1000)
                .isZero();

        assertThat(refreshToken.getExpiresAt().getNano() % 1000)
                .isZero();

        assertThat(result.sessionExpiresAt().getNano() % 1000)
                .isZero();

        assertThat(result.refreshTokenExpiresAt().getNano() % 1000)
                .isZero();
    }


    @Test
    void issue_sessionAndTokenShareCreationTimestamp() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        assertThat(session.getCreatedAt())
                .isEqualTo(refreshToken.getCreatedAt());
    }


    @Test
    void issue_usesConfiguredSessionTtl() {
        Duration customSessionTtl = Duration.ofDays(60);

        AuthProperties customProperties =
                new AuthProperties(
                        REFRESH_TOKEN_TTL,
                        customSessionTtl
                );

        RefreshTokenIssuanceService customService =
                new RefreshTokenIssuanceService(
                        authSessionRepository,
                        refreshTokenRepository,
                        refreshTokenGenerator,
                        customProperties,
                        clock
                );

        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                customService.issue(userId);

        AuthSession session = captureSession();

        Instant expectedExpiration =
                EXPECTED_CREATED_AT.plus(customSessionTtl);

        assertThat(session.getExpiresAt())
                .isEqualTo(expectedExpiration);

        assertThat(result.sessionExpiresAt())
                .isEqualTo(expectedExpiration);
    }


    @Test
    void issue_usesConfiguredRefreshTokenTtl() {
        Duration customRefreshTokenTtl = Duration.ofDays(14);

        AuthProperties customProperties =
                new AuthProperties(
                        customRefreshTokenTtl,
                        SESSION_TTL
                );

        RefreshTokenIssuanceService customService =
                new RefreshTokenIssuanceService(
                        authSessionRepository,
                        refreshTokenRepository,
                        refreshTokenGenerator,
                        customProperties,
                        clock
                );

        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                customService.issue(userId);

        RefreshToken refreshToken = captureRefreshToken();

        Instant expectedExpiration =
                EXPECTED_CREATED_AT.plus(customRefreshTokenTtl);

        assertThat(refreshToken.getExpiresAt())
                .isEqualTo(expectedExpiration);

        assertThat(result.refreshTokenExpiresAt())
                .isEqualTo(expectedExpiration);
    }

    @Test
    void issue_withEqualTtls_tokenAndSessionExpireTogether() {
        Duration equalTtl = Duration.ofDays(30);

        AuthProperties customProperties =
                new AuthProperties(
                        equalTtl,
                        equalTtl
                );

        RefreshTokenIssuanceService customService =
                new RefreshTokenIssuanceService(
                        authSessionRepository,
                        refreshTokenRepository,
                        refreshTokenGenerator,
                        customProperties,
                        clock
                );

        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                customService.issue(userId);

        AuthSession session = captureSession();
        RefreshToken refreshToken = captureRefreshToken();

        Instant expectedExpiration =
                EXPECTED_CREATED_AT.plus(equalTtl);

        assertThat(session.getExpiresAt())
                .isEqualTo(expectedExpiration);

        assertThat(refreshToken.getExpiresAt())
                .isEqualTo(expectedExpiration);

        assertThat(result.sessionExpiresAt())
                .isEqualTo(expectedExpiration);

        assertThat(result.refreshTokenExpiresAt())
                .isEqualTo(expectedExpiration);
    }


    @Test
    void issue_generatesRawTokenExactlyOnce() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        verify(refreshTokenGenerator, times(1))
                .generate();
    }


    @Test
    void issue_hashesGeneratedRawToken() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        verify(refreshTokenGenerator, times(1))
                .hash(rawRefreshToken);

        verifyNoMoreInteractions(refreshTokenGenerator);
    }


    @Test
    void issue_generatesAndHashesBeforePersistence() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        InOrder inOrder = inOrder(
                refreshTokenGenerator,
                authSessionRepository,
                refreshTokenRepository
        );

        inOrder.verify(refreshTokenGenerator)
                .generate();

        inOrder.verify(refreshTokenGenerator)
                .hash(rawRefreshToken);

        inOrder.verify(authSessionRepository)
                .saveAndFlush(any(AuthSession.class));

        inOrder.verify(refreshTokenRepository)
                .saveAndFlush(any(RefreshToken.class));

        inOrder.verifyNoMoreInteractions();
    }


    @Test
    void issue_persistsSessionBeforeRefreshToken() {
        mockSuccessfulTokenGeneration();

        issuanceService.issue(userId);

        InOrder inOrder = inOrder(
                authSessionRepository,
                refreshTokenRepository
        );

        inOrder.verify(authSessionRepository)
                .saveAndFlush(any(AuthSession.class));

        inOrder.verify(refreshTokenRepository)
                .saveAndFlush(any(RefreshToken.class));

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }


    @Test
    void issue_returnsRawTokenInsteadOfTokenHash() {
        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        RefreshToken refreshToken = captureRefreshToken();

        assertThat(result.rawRefreshToken())
                .isEqualTo(rawRefreshToken)
                .isNotEqualTo(tokenHash);

        assertThat(refreshToken.getTokenHash())
                .isEqualTo(tokenHash)
                .isNotEqualTo(result.rawRefreshToken());
    }


    @Test
    void issuanceResultToString_doesNotExposeRawRefreshToken() {
        mockSuccessfulTokenGeneration();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        assertThat(result.toString())
                .doesNotContain(rawRefreshToken)
                .doesNotContain(tokenHash)
                .contains("rawRefreshToken=REDACTED")
                .contains("sessionId=" + result.sessionId())
                .contains("refreshTokenExpiresAt="
                        + result.refreshTokenExpiresAt())
                .contains("sessionExpiresAt="
                        + result.sessionExpiresAt());
    }


    @Test
    void issue_whenTokenGenerationFails_propagatesException() {
        IllegalStateException exception =
                new IllegalStateException("Token generation failed");

        when(refreshTokenGenerator.generate())
                .thenThrow(exception);

        assertThatThrownBy(() -> issuanceService.issue(userId))
                .isSameAs(exception);

        verify(refreshTokenGenerator).generate();

        verifyNoMoreInteractions(refreshTokenGenerator);

        verifyNoInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }


    @Test
    void issue_whenTokenHashingFails_propagatesException() {
        IllegalStateException exception =
                new IllegalStateException("Token hashing failed");

        when(refreshTokenGenerator.generate())
                .thenReturn(rawRefreshToken);

        when(refreshTokenGenerator.hash(rawRefreshToken))
                .thenThrow(exception);

        assertThatThrownBy(() -> issuanceService.issue(userId))
                .isSameAs(exception);

        verify(refreshTokenGenerator).generate();

        verify(refreshTokenGenerator).hash(rawRefreshToken);

        verifyNoMoreInteractions(refreshTokenGenerator);

        verifyNoInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }


    @Test
    void issue_whenSessionPersistenceFails_doesNotPersistToken() {
        mockSuccessfulTokenGeneration();

        DataIntegrityViolationException exception =
                new DataIntegrityViolationException(
                        "Session persistence failed"
                );

        when(authSessionRepository.saveAndFlush(
                any(AuthSession.class)
        )).thenThrow(exception);

        assertThatThrownBy(() -> issuanceService.issue(userId))
                .isSameAs(exception);

        verify(authSessionRepository)
                .saveAndFlush(any(AuthSession.class));

        verify(refreshTokenRepository, never())
                .saveAndFlush(any(RefreshToken.class));

        verifyNoInteractions(refreshTokenRepository);
    }


    @Test
    void issue_whenRefreshTokenPersistenceFails_propagatesException() {
        mockSuccessfulTokenGeneration();

        DataIntegrityViolationException exception =
                new DataIntegrityViolationException(
                        "Refresh token persistence failed"
                );

        when(refreshTokenRepository.saveAndFlush(
                any(RefreshToken.class)
        )).thenThrow(exception);

        assertThatThrownBy(() -> issuanceService.issue(userId))
                .isSameAs(exception);

        InOrder inOrder = inOrder(
                authSessionRepository,
                refreshTokenRepository
        );

        inOrder.verify(authSessionRepository)
                .saveAndFlush(any(AuthSession.class));

        inOrder.verify(refreshTokenRepository)
                .saveAndFlush(any(RefreshToken.class));

        verifyNoMoreInteractions(
                authSessionRepository,
                refreshTokenRepository
        );
    }




}
