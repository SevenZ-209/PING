
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import com.ping.backend.support.MutableClock;
import com.ping.backend.validation.RefreshTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import org.junit.jupiter.api.AfterEach;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.exception.InvalidRefreshTokenException;
import org.springframework.dao.DataIntegrityViolationException;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doCallRealMethod;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import org.springframework.transaction.IllegalTransactionStateException;
import org.springframework.transaction.support.TransactionTemplate;

import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verifyNoInteractions;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "auth.refresh-token-ttl=30d",
        "auth.session-ttl=90d"
})
@Import(
        RefreshTokenRotationServiceIntegrationTest
                .ClockConfiguration.class
)
class RefreshTokenRotationServiceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    private static final Instant INITIAL_TIME =
            Instant.parse("2026-01-01T00:00:00Z");

    private static final Duration REFRESH_TOKEN_TTL =
            Duration.ofDays(30);

    private static final Duration SESSION_TTL =
            Duration.ofDays(90);

    private final List<UUID> createdUserIds =
            new ArrayList<>();


    private UUID createUser() {
        UUID userId = UUID.randomUUID();

        jdbcClient.sql("""
            INSERT INTO users
                (id, email, password_hash, display_name)
            VALUES
                (:id, :email, :passwordHash, :displayName)
            """)
                .param("id", userId)
                .param("email", userId + "@example.com")
                .param("passwordHash", "test-hash")
                .param("displayName", "Test User")
                .update();

        createdUserIds.add(userId);

        return userId;
    }


    private RefreshTokenIssuanceResult issueRefreshToken(
            UUID userId
    ) {
        return issuanceService.issue(userId);
    }


    private Map<String, Object> findSession(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT id, user_id, created_at,
                   expires_at, revoked_at
            FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query()
                .singleRow();
    }


    private Map<String, Object> findTokenByHash(
            String tokenHash
    ) {
        return jdbcClient.sql("""
            SELECT id, session_id, token_hash,
                   created_at, expires_at, consumed_at
            FROM auth_refresh_tokens
            WHERE token_hash = :tokenHash
            """)
                .param("tokenHash", tokenHash)
                .query()
                .singleRow();
    }


    private long countSessions(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }


    private long countTokens(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(Long.class)
                .single();
    }


    private long countUnconsumedTokens(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("sessionId", sessionId)
                .query(Long.class)
                .single();
    }


    private Instant readTimestamp(
            Map<String, Object> row,
            String column
    ) {
        if (!row.containsKey(column)) {
            throw new IllegalArgumentException(
                    "Missing timestamp column: " + column
            );
        }

        Object value = row.get(column);

        if (value == null) {
            return null;
        }

        if (value instanceof java.sql.Timestamp timestamp) {
            return timestamp.toInstant();
        }

        if (value instanceof OffsetDateTime offsetDateTime) {
            return offsetDateTime.toInstant();
        }

        if (value instanceof Instant instant) {
            return instant;
        }

        throw new IllegalStateException(
                "Unsupported timestamp value: " + column
        );
    }


    @AfterEach
    void cleanupTestData() {
        for (UUID userId : createdUserIds) {
            jdbcClient.sql("""
                DELETE FROM users
                WHERE id = :userId
                """)
                    .param("userId", userId)
                    .update();
        }

        createdUserIds.clear();
    }


    @TestConfiguration(proxyBeanMethods = false)
    static class ClockConfiguration {

        @Bean
        @Primary
        MutableClock mutableTestClock() {
            return new MutableClock(
                    INITIAL_TIME,
                    ZoneOffset.UTC
            );
        }
    }

    @Autowired
    private RefreshTokenIssuanceService issuanceService;

    @Autowired
    private RefreshTokenRotationService rotationService;

    @Autowired
    private RefreshTokenRotationTransactionService transactionService;

    @Autowired
    private AuthSessionRepository authSessionRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @MockitoSpyBean
    private RefreshTokenGenerator refreshTokenGenerator;

    @Autowired
    private RefreshTokenValidator refreshTokenValidator;

    @Autowired
    private AuthProperties authProperties;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private MutableClock mutableClock;

    @Autowired
    private Clock clock;

    @Autowired
    private PlatformTransactionManager transactionManager;

    @Autowired
    private Environment environment;

    @BeforeEach
    void resetClock() {
        mutableClock.setInstant(INITIAL_TIME);
    }

    @Test
    void contextLoads_withRequiredIntegrationInfrastructure() {
        assertThat(postgres.isRunning()).isTrue();

        assertThat(
                jdbcClient.sql("SELECT 1")
                        .query(Integer.class)
                        .single()
        ).isEqualTo(1);

        assertThat(issuanceService).isNotNull();

        assertThat(rotationService).isNotNull();

        assertThat(transactionService).isNotNull();

        assertThat(authSessionRepository).isNotNull();

        assertThat(refreshTokenRepository).isNotNull();

        assertThat(refreshTokenGenerator).isNotNull();

        assertThat(refreshTokenValidator).isNotNull();

        assertThat(transactionManager).isNotNull();

        assertThat(AopUtils.isAopProxy(rotationService))
                .isTrue();

        assertThat(AopUtils.isAopProxy(transactionService))
                .isTrue();

        assertThat(clock).isSameAs(mutableClock);

        assertThat(clock.instant())
                .isEqualTo(INITIAL_TIME);

        assertThat(clock.getZone())
                .isEqualTo(ZoneOffset.UTC);

        assertThat(authProperties.refreshTokenTtl())
                .isEqualTo(REFRESH_TOKEN_TTL);

        assertThat(authProperties.sessionTtl())
                .isEqualTo(SESSION_TTL);

        assertThat(environment.getProperty(
                "spring.jpa.open-in-view",
                Boolean.class
        )).isFalse();

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void databaseFixtures_createUserSessionAndRefreshToken() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String tokenHash = refreshTokenGenerator.hash(
                issuanceResult.rawRefreshToken()
        );

        Map<String, Object> sessionRow =
                findSession(sessionId);

        Map<String, Object> tokenRow =
                findTokenByHash(tokenHash);

        assertThat(sessionRow.get("id"))
                .isEqualTo(sessionId);

        assertThat(sessionRow.get("user_id"))
                .isEqualTo(userId);

        assertThat(readTimestamp(sessionRow, "created_at"))
                .isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(sessionRow, "expires_at"))
                .isEqualTo(INITIAL_TIME.plus(SESSION_TTL));

        assertThat(readTimestamp(sessionRow, "revoked_at"))
                .isNull();

        assertThat(tokenRow.get("id")).isNotNull();

        assertThat(tokenRow.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(tokenRow.get("token_hash"))
                .isEqualTo(tokenHash);

        assertThat(readTimestamp(tokenRow, "created_at"))
                .isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(tokenRow, "expires_at"))
                .isEqualTo(INITIAL_TIME.plus(REFRESH_TOKEN_TTL));

        assertThat(readTimestamp(tokenRow, "consumed_at"))
                .isNull();

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void rotate_whenTokenIsValid_persistsConsumptionAndReplacement() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        Map<String, Object> originalTokenBeforeRotation =
                findTokenByHash(originalTokenHash);

        mutableClock.advance(Duration.ofDays(10));

        Instant rotationTime = mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementRawToken =
                rotationResult.rawRefreshToken();

        String replacementTokenHash =
                refreshTokenGenerator.hash(replacementRawToken);

        assertThat(rotationResult.userId())
                .isEqualTo(userId);

        assertThat(rotationResult.sessionId())
                .isEqualTo(sessionId);

        assertThat(replacementRawToken)
                .isNotBlank()
                .isNotEqualTo(originalRawToken);

        assertThat(replacementTokenHash)
                .isNotEqualTo(originalTokenHash);

        assertThat(refreshTokenValidator.validate(replacementRawToken))
                .isEqualTo(replacementRawToken);

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isEqualTo(rotationTime.plus(REFRESH_TOKEN_TTL));

        assertThat(rotationResult.sessionExpiresAt())
                .isEqualTo(issuanceResult.sessionExpiresAt());

        Map<String, Object> originalTokenAfterRotation =
                findTokenByHash(originalTokenHash);

        assertThat(originalTokenAfterRotation.get("id"))
                .isEqualTo(originalTokenBeforeRotation.get("id"));

        assertThat(originalTokenAfterRotation.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(originalTokenAfterRotation.get("token_hash"))
                .isEqualTo(originalTokenHash);

        assertThat(readTimestamp(
                originalTokenAfterRotation,
                "created_at"
        )).isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(
                originalTokenAfterRotation,
                "expires_at"
        )).isEqualTo(issuanceResult.refreshTokenExpiresAt());

        assertThat(readTimestamp(
                originalTokenAfterRotation,
                "consumed_at"
        )).isEqualTo(rotationTime);

        Map<String, Object> replacementTokenRow =
                findTokenByHash(replacementTokenHash);

        assertThat(replacementTokenRow.get("id"))
                .isNotNull()
                .isNotEqualTo(originalTokenAfterRotation.get("id"));

        assertThat(replacementTokenRow.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(replacementTokenRow.get("token_hash"))
                .isEqualTo(replacementTokenHash)
                .isNotEqualTo(replacementRawToken);

        assertThat(readTimestamp(
                replacementTokenRow,
                "created_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                replacementTokenRow,
                "expires_at"
        )).isEqualTo(rotationResult.refreshTokenExpiresAt());

        assertThat(readTimestamp(
                replacementTokenRow,
                "consumed_at"
        )).isNull();

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void rotate_whenSuccessful_preservesOriginalSession() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        Map<String, Object> sessionBeforeRotation =
                findSession(sessionId);

        mutableClock.advance(Duration.ofDays(20));

        Instant rotationTime = mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(
                        issuanceResult.rawRefreshToken()
                );

        Map<String, Object> sessionAfterRotation =
                findSession(sessionId);

        assertThat(sessionAfterRotation)
                .isEqualTo(sessionBeforeRotation);

        assertThat(sessionAfterRotation.get("id"))
                .isEqualTo(sessionId);

        assertThat(sessionAfterRotation.get("user_id"))
                .isEqualTo(userId);

        assertThat(readTimestamp(
                sessionAfterRotation,
                "created_at"
        )).isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(
                sessionAfterRotation,
                "expires_at"
        )).isEqualTo(INITIAL_TIME.plus(SESSION_TTL));

        assertThat(readTimestamp(
                sessionAfterRotation,
                "revoked_at"
        )).isNull();

        assertThat(rotationResult.sessionId())
                .isEqualTo(sessionId);

        assertThat(rotationResult.sessionExpiresAt())
                .isEqualTo(issuanceResult.sessionExpiresAt());

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isEqualTo(rotationTime.plus(REFRESH_TOKEN_TTL));

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenCalledSequentially_preservesTokenHistory() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String currentRawToken =
                issuanceResult.rawRefreshToken();

        Instant sessionExpiration =
                issuanceResult.sessionExpiresAt();

        Map<String, Object> originalSession =
                findSession(sessionId);

        List<String> tokenHashes = new ArrayList<>();

        tokenHashes.add(
                refreshTokenGenerator.hash(currentRawToken)
        );

        for (int rotationNumber = 1;
             rotationNumber <= 3;
             rotationNumber++) {

            mutableClock.advance(Duration.ofDays(20));

            Instant rotationTime = mutableClock.instant();

            String previousTokenHash =
                    refreshTokenGenerator.hash(currentRawToken);

            RefreshTokenRotationResult rotationResult =
                    rotationService.rotate(currentRawToken);

            String replacementRawToken =
                    rotationResult.rawRefreshToken();

            String replacementTokenHash =
                    refreshTokenGenerator.hash(replacementRawToken);

            assertThat(replacementRawToken)
                    .isNotEqualTo(currentRawToken);

            assertThat(tokenHashes)
                    .doesNotContain(replacementTokenHash);

            tokenHashes.add(replacementTokenHash);

            assertThat(rotationResult.userId())
                    .isEqualTo(userId);

            assertThat(rotationResult.sessionId())
                    .isEqualTo(sessionId);

            assertThat(rotationResult.sessionExpiresAt())
                    .isEqualTo(sessionExpiration);

            assertThat(rotationResult.refreshTokenExpiresAt())
                    .isEqualTo(
                            rotationTime.plus(REFRESH_TOKEN_TTL)
                    );

            Map<String, Object> previousTokenRow =
                    findTokenByHash(previousTokenHash);

            Map<String, Object> replacementTokenRow =
                    findTokenByHash(replacementTokenHash);

            assertThat(readTimestamp(
                    previousTokenRow,
                    "consumed_at"
            )).isEqualTo(rotationTime);

            assertThat(replacementTokenRow.get("session_id"))
                    .isEqualTo(sessionId);

            assertThat(readTimestamp(
                    replacementTokenRow,
                    "created_at"
            )).isEqualTo(rotationTime);

            assertThat(readTimestamp(
                    replacementTokenRow,
                    "expires_at"
            )).isEqualTo(
                    rotationResult.refreshTokenExpiresAt()
            );

            assertThat(readTimestamp(
                    replacementTokenRow,
                    "consumed_at"
            )).isNull();

            assertThat(countSessions(userId))
                    .isEqualTo(1L);

            assertThat(countTokens(sessionId))
                    .isEqualTo(rotationNumber + 1L);

            assertThat(countUnconsumedTokens(sessionId))
                    .isEqualTo(1L);

            assertThat(findSession(sessionId))
                    .isEqualTo(originalSession);

            assertThat(TransactionSynchronizationManager
                    .isActualTransactionActive())
                    .isFalse();

            currentRawToken = replacementRawToken;
        }

        assertThat(tokenHashes)
                .hasSize(4)
                .doesNotHaveDuplicates();

        for (int index = 0;
             index < tokenHashes.size() - 1;
             index++) {

            Map<String, Object> tokenRow =
                    findTokenByHash(tokenHashes.get(index));

            Instant expectedConsumedAt =
                    INITIAL_TIME.plus(
                            Duration.ofDays((index + 1L) * 20)
                    );

            assertThat(readTimestamp(
                    tokenRow,
                    "consumed_at"
            )).isEqualTo(expectedConsumedAt);
        }

        Map<String, Object> latestTokenRow =
                findTokenByHash(
                        tokenHashes.get(tokenHashes.size() - 1)
                );

        assertThat(readTimestamp(
                latestTokenRow,
                "consumed_at"
        )).isNull();

        assertThat(countTokens(sessionId))
                .isEqualTo(4L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenRefreshTtlExceedsSessionLifetime_capsExpiration() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        Instant sessionExpiration =
                issuanceResult.sessionExpiresAt();

        Map<String, Object> originalSession =
                findSession(sessionId);

        mutableClock.advance(Duration.ofDays(25));

        RefreshTokenRotationResult firstRotation =
                rotationService.rotate(
                        issuanceResult.rawRefreshToken()
                );

        assertThat(firstRotation.refreshTokenExpiresAt())
                .isEqualTo(
                        INITIAL_TIME.plus(Duration.ofDays(55))
                );

        mutableClock.advance(Duration.ofDays(25));

        RefreshTokenRotationResult secondRotation =
                rotationService.rotate(
                        firstRotation.rawRefreshToken()
                );

        assertThat(secondRotation.refreshTokenExpiresAt())
                .isEqualTo(
                        INITIAL_TIME.plus(Duration.ofDays(80))
                );

        mutableClock.advance(Duration.ofDays(25));

        Instant rotationTime = mutableClock.instant();

        Instant uncappedExpiration =
                rotationTime.plus(REFRESH_TOKEN_TTL);

        assertThat(uncappedExpiration)
                .isAfter(sessionExpiration);

        String previousTokenHash =
                refreshTokenGenerator.hash(
                        secondRotation.rawRefreshToken()
                );

        RefreshTokenRotationResult finalRotation =
                rotationService.rotate(
                        secondRotation.rawRefreshToken()
                );

        assertThat(finalRotation.userId())
                .isEqualTo(userId);

        assertThat(finalRotation.sessionId())
                .isEqualTo(sessionId);

        assertThat(finalRotation.sessionExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(finalRotation.refreshTokenExpiresAt())
                .isEqualTo(sessionExpiration);

        assertThat(finalRotation.refreshTokenExpiresAt())
                .isBefore(uncappedExpiration);

        String finalTokenHash =
                refreshTokenGenerator.hash(
                        finalRotation.rawRefreshToken()
                );

        Map<String, Object> previousTokenRow =
                findTokenByHash(previousTokenHash);

        Map<String, Object> finalTokenRow =
                findTokenByHash(finalTokenHash);

        assertThat(readTimestamp(
                previousTokenRow,
                "consumed_at"
        )).isEqualTo(rotationTime);

        assertThat(finalTokenRow.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(readTimestamp(
                finalTokenRow,
                "created_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                finalTokenRow,
                "expires_at"
        )).isEqualTo(sessionExpiration);

        assertThat(readTimestamp(
                finalTokenRow,
                "consumed_at"
        )).isNull();

        assertThat(Duration.between(
                readTimestamp(finalTokenRow, "created_at"),
                readTimestamp(finalTokenRow, "expires_at")
        )).isEqualTo(Duration.ofDays(15));

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(4L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenConsumedTokenIsReused_commitsSessionRevocationBeforeThrowing() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        Instant originalConsumedAt =
                mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementTokenHash =
                refreshTokenGenerator.hash(
                        rotationResult.rawRefreshToken()
                );

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalTokenBeforeReuse =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementTokenBeforeReuse =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                originalSession,
                "revoked_at"
        )).isNull();

        assertThat(readTimestamp(
                originalTokenBeforeReuse,
                "consumed_at"
        )).isEqualTo(originalConsumedAt);

        assertThat(readTimestamp(
                replacementTokenBeforeReuse,
                "consumed_at"
        )).isNull();

        mutableClock.advance(Duration.ofDays(5));

        Instant reuseTime = mutableClock.instant();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();

        Map<String, Object> revokedSession =
                findSession(sessionId);

        assertThat(readTimestamp(
                revokedSession,
                "revoked_at"
        )).isEqualTo(reuseTime);

        assertThat(revokedSession.get("id"))
                .isEqualTo(sessionId);

        assertThat(revokedSession.get("user_id"))
                .isEqualTo(userId);

        assertThat(readTimestamp(
                revokedSession,
                "created_at"
        )).isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(
                revokedSession,
                "expires_at"
        )).isEqualTo(
                issuanceResult.sessionExpiresAt()
        );

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalTokenBeforeReuse);

        assertThat(findTokenByHash(replacementTokenHash))
                .isEqualTo(replacementTokenBeforeReuse);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenSessionWasRevokedByReuse_rejectsReplacementToken() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementRawToken =
                rotationResult.rawRefreshToken();

        String replacementTokenHash =
                refreshTokenGenerator.hash(replacementRawToken);

        mutableClock.advance(Duration.ofDays(5));

        Instant revocationTime = mutableClock.instant();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        ).isInstanceOf(InvalidRefreshTokenException.class);

        Map<String, Object> revokedSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                revokedSession,
                "revoked_at"
        )).isEqualTo(revocationTime);

        mutableClock.advance(Duration.ofDays(1));

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isAfter(mutableClock.instant());

        assertThat(readTimestamp(
                replacementToken,
                "consumed_at"
        )).isNull();

        assertThatThrownBy(() ->
                rotationService.rotate(replacementRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(findSession(sessionId))
                .isEqualTo(revokedSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalToken);

        assertThat(findTokenByHash(replacementTokenHash))
                .isEqualTo(replacementToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenExpiredConsumedTokenIsReused_commitsSessionRevocation() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        Instant originalConsumedAt =
                mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementTokenHash =
                refreshTokenGenerator.hash(
                        rotationResult.rawRefreshToken()
                );

        mutableClock.advance(Duration.ofDays(25));

        Instant reuseTime = mutableClock.instant();

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        Map<String, Object> sessionBeforeReuse =
                findSession(sessionId);

        assertThat(readTimestamp(
                originalToken,
                "expires_at"
        )).isBefore(reuseTime);

        assertThat(readTimestamp(
                originalToken,
                "consumed_at"
        )).isEqualTo(originalConsumedAt);

        assertThat(readTimestamp(
                replacementToken,
                "expires_at"
        )).isAfter(reuseTime);

        assertThat(readTimestamp(
                sessionBeforeReuse,
                "expires_at"
        )).isAfter(reuseTime);

        assertThat(readTimestamp(
                sessionBeforeReuse,
                "revoked_at"
        )).isNull();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        Map<String, Object> revokedSession =
                findSession(sessionId);

        assertThat(readTimestamp(
                revokedSession,
                "revoked_at"
        )).isEqualTo(reuseTime);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalToken);

        assertThat(findTokenByHash(replacementTokenHash))
                .isEqualTo(replacementToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenConsumedTokenIsRepeatedlyReused_preservesOriginalRevocation() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementTokenHash =
                refreshTokenGenerator.hash(
                        rotationResult.rawRefreshToken()
                );

        mutableClock.advance(Duration.ofDays(5));

        Instant originalRevokedAt =
                mutableClock.instant();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        ).isInstanceOf(InvalidRefreshTokenException.class);

        Map<String, Object> revokedSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                revokedSession,
                "revoked_at"
        )).isEqualTo(originalRevokedAt);

        for (int attempt = 0; attempt < 3; attempt++) {
            mutableClock.advance(Duration.ofDays(1));

            assertThatThrownBy(() ->
                    rotationService.rotate(originalRawToken)
            )
                    .isInstanceOf(InvalidRefreshTokenException.class)
                    .hasMessage("Invalid or expired refresh token");

            assertThat(findSession(sessionId))
                    .isEqualTo(revokedSession);

            assertThat(findTokenByHash(originalTokenHash))
                    .isEqualTo(originalToken);

            assertThat(findTokenByHash(replacementTokenHash))
                    .isEqualTo(replacementToken);

            assertThat(countTokens(sessionId))
                    .isEqualTo(2L);

            assertThat(countUnconsumedTokens(sessionId))
                    .isEqualTo(1L);
        }

        assertThat(readTimestamp(
                findSession(sessionId),
                "revoked_at"
        )).isEqualTo(originalRevokedAt);

        assertThat(countSessions(userId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenTokenIsUnknown_rejectsWithoutChangingExistingSession() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String existingTokenHash =
                refreshTokenGenerator.hash(
                        issuanceResult.rawRefreshToken()
                );

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(existingTokenHash);

        String unknownRawToken =
                refreshTokenGenerator.generate();

        String unknownTokenHash =
                refreshTokenGenerator.hash(unknownRawToken);

        assertThat(unknownTokenHash)
                .isNotEqualTo(existingTokenHash);

        assertThat(
                refreshTokenRepository.findByTokenHash(
                        unknownTokenHash
                )
        ).isEmpty();

        mutableClock.advance(Duration.ofDays(10));

        assertThatThrownBy(() ->
                rotationService.rotate(unknownRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(existingTokenHash))
                .isEqualTo(originalToken);

        assertThat(
                refreshTokenRepository.findByTokenHash(
                        unknownTokenHash
                )
        ).isEmpty();

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenUnconsumedTokenHasExpired_doesNotRevokeSession() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String rawToken =
                issuanceResult.rawRefreshToken();

        String tokenHash =
                refreshTokenGenerator.hash(rawToken);

        mutableClock.advance(REFRESH_TOKEN_TTL);

        Instant rotationTime = mutableClock.instant();

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(tokenHash);

        assertThat(readTimestamp(
                originalToken,
                "expires_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                originalToken,
                "consumed_at"
        )).isNull();

        assertThat(readTimestamp(
                originalSession,
                "expires_at"
        )).isAfter(rotationTime);

        assertThat(readTimestamp(
                originalSession,
                "revoked_at"
        )).isNull();

        assertThatThrownBy(() ->
                rotationService.rotate(rawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(tokenHash))
                .isEqualTo(originalToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenSessionHasExpired_rejectsWithoutChangingDatabaseState() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementRawToken =
                rotationResult.rawRefreshToken();

        String replacementTokenHash =
                refreshTokenGenerator.hash(replacementRawToken);

        mutableClock.setInstant(
                issuanceResult.sessionExpiresAt()
        );

        Instant rotationTime = mutableClock.instant();

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                originalSession,
                "expires_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                originalSession,
                "revoked_at"
        )).isNull();

        assertThat(readTimestamp(
                originalToken,
                "consumed_at"
        )).isNotNull();

        assertThat(readTimestamp(
                replacementToken,
                "consumed_at"
        )).isNull();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThatThrownBy(() ->
                rotationService.rotate(replacementRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalToken);

        assertThat(findTokenByHash(replacementTokenHash))
                .isEqualTo(replacementToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenReuseRevokesOneSession_doesNotAffectOtherSessionOfSameUser() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult firstIssuance =
                issueRefreshToken(userId);

        RefreshTokenIssuanceResult secondIssuance =
                issueRefreshToken(userId);

        UUID firstSessionId =
                firstIssuance.sessionId();

        UUID secondSessionId =
                secondIssuance.sessionId();

        assertThat(firstSessionId)
                .isNotEqualTo(secondSessionId);

        String firstOriginalRawToken =
                firstIssuance.rawRefreshToken();

        String firstOriginalTokenHash =
                refreshTokenGenerator.hash(
                        firstOriginalRawToken
                );

        String secondOriginalRawToken =
                secondIssuance.rawRefreshToken();

        String secondOriginalTokenHash =
                refreshTokenGenerator.hash(
                        secondOriginalRawToken
                );

        mutableClock.advance(Duration.ofDays(10));

        RefreshTokenRotationResult firstRotation =
                rotationService.rotate(
                        firstOriginalRawToken
                );

        String firstReplacementTokenHash =
                refreshTokenGenerator.hash(
                        firstRotation.rawRefreshToken()
                );

        Map<String, Object> secondSessionBeforeReuse =
                findSession(secondSessionId);

        Map<String, Object> secondTokenBeforeReuse =
                findTokenByHash(secondOriginalTokenHash);

        assertThat(countSessions(userId))
                .isEqualTo(2L);

        mutableClock.advance(Duration.ofDays(5));

        Instant reuseTime = mutableClock.instant();

        assertThatThrownBy(() ->
                rotationService.rotate(
                        firstOriginalRawToken
                )
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        Map<String, Object> firstRevokedSession =
                findSession(firstSessionId);

        assertThat(readTimestamp(
                firstRevokedSession,
                "revoked_at"
        )).isEqualTo(reuseTime);

        assertThat(findSession(secondSessionId))
                .isEqualTo(secondSessionBeforeReuse);

        assertThat(findTokenByHash(secondOriginalTokenHash))
                .isEqualTo(secondTokenBeforeReuse);

        assertThat(readTimestamp(
                findSession(secondSessionId),
                "revoked_at"
        )).isNull();

        Map<String, Object> firstOriginalToken =
                findTokenByHash(firstOriginalTokenHash);

        Map<String, Object> firstReplacementToken =
                findTokenByHash(firstReplacementTokenHash);

        mutableClock.advance(Duration.ofDays(1));

        Instant secondRotationTime =
                mutableClock.instant();

        RefreshTokenRotationResult secondRotation =
                rotationService.rotate(
                        secondOriginalRawToken
                );

        assertThat(secondRotation.userId())
                .isEqualTo(userId);

        assertThat(secondRotation.sessionId())
                .isEqualTo(secondSessionId);

        assertThat(secondRotation.sessionExpiresAt())
                .isEqualTo(
                        secondIssuance.sessionExpiresAt()
                );

        String secondReplacementTokenHash =
                refreshTokenGenerator.hash(
                        secondRotation.rawRefreshToken()
                );

        Map<String, Object> secondReplacementToken =
                findTokenByHash(
                        secondReplacementTokenHash
                );

        assertThat(secondReplacementToken.get("session_id"))
                .isEqualTo(secondSessionId);

        assertThat(readTimestamp(
                secondReplacementToken,
                "consumed_at"
        )).isNull();

        assertThat(readTimestamp(
                findTokenByHash(secondOriginalTokenHash),
                "consumed_at"
        )).isEqualTo(secondRotationTime);

        assertThat(findSession(firstSessionId))
                .isEqualTo(firstRevokedSession);

        assertThat(findSession(secondSessionId))
                .isEqualTo(secondSessionBeforeReuse);

        assertThat(findTokenByHash(firstOriginalTokenHash))
                .isEqualTo(firstOriginalToken);

        assertThat(findTokenByHash(firstReplacementTokenHash))
                .isEqualTo(firstReplacementToken);

        assertThat(countSessions(userId))
                .isEqualTo(2L);

        assertThat(countTokens(firstSessionId))
                .isEqualTo(2L);

        assertThat(countTokens(secondSessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(firstSessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(secondSessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_whenReplacementTokenHashAlreadyExists_rollsBackConsumption() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        Map<String, Object> sessionBeforeRotation =
                findSession(sessionId);

        Map<String, Object> tokenBeforeRotation =
                findTokenByHash(originalTokenHash);

        assertThat(readTimestamp(
                tokenBeforeRotation,
                "consumed_at"
        )).isNull();

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        mutableClock.advance(Duration.ofDays(10));

        doReturn(originalRawToken)
                .when(refreshTokenGenerator)
                .generate();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        )
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasStackTraceContaining(
                        "uq_auth_refresh_tokens_hash"
                );

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();

        Map<String, Object> sessionAfterFailure =
                findSession(sessionId);

        Map<String, Object> tokenAfterFailure =
                findTokenByHash(originalTokenHash);

        assertThat(sessionAfterFailure)
                .isEqualTo(sessionBeforeRotation);

        assertThat(tokenAfterFailure)
                .isEqualTo(tokenBeforeRotation);

        assertThat(readTimestamp(
                tokenAfterFailure,
                "consumed_at"
        )).isNull();

        assertThat(readTimestamp(
                sessionAfterFailure,
                "revoked_at"
        )).isNull();

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_afterFailedReplacementPersistence_allowsOriginalTokenToRotate() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        mutableClock.advance(Duration.ofDays(10));

        doReturn(originalRawToken)
                .when(refreshTokenGenerator)
                .generate();

        assertThatThrownBy(() ->
                rotationService.rotate(originalRawToken)
        )
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasStackTraceContaining(
                        "uq_auth_refresh_tokens_hash"
                );

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalToken);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        doCallRealMethod()
                .when(refreshTokenGenerator)
                .generate();

        mutableClock.advance(Duration.ofDays(1));

        Instant successfulRotationTime =
                mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementRawToken =
                rotationResult.rawRefreshToken();

        String replacementTokenHash =
                refreshTokenGenerator.hash(replacementRawToken);

        assertThat(rotationResult.userId())
                .isEqualTo(userId);

        assertThat(rotationResult.sessionId())
                .isEqualTo(sessionId);

        assertThat(replacementRawToken)
                .isNotEqualTo(originalRawToken);

        assertThat(replacementTokenHash)
                .isNotEqualTo(originalTokenHash);

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isEqualTo(
                        successfulRotationTime.plus(REFRESH_TOKEN_TTL)
                );

        assertThat(rotationResult.sessionExpiresAt())
                .isEqualTo(
                        issuanceResult.sessionExpiresAt()
                );

        Map<String, Object> consumedToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                consumedToken,
                "consumed_at"
        )).isEqualTo(successfulRotationTime);

        assertThat(readTimestamp(
                replacementToken,
                "created_at"
        )).isEqualTo(successfulRotationTime);

        assertThat(readTimestamp(
                replacementToken,
                "expires_at"
        )).isEqualTo(
                rotationResult.refreshTokenExpiresAt()
        );

        assertThat(readTimestamp(
                replacementToken,
                "consumed_at"
        )).isNull();

        assertThat(replacementToken.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void rotate_whenCalledInsideExistingTransaction_rejectsInvocation() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String rawToken =
                issuanceResult.rawRefreshToken();

        String tokenHash =
                refreshTokenGenerator.hash(rawToken);

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(tokenHash);

        mutableClock.advance(Duration.ofDays(10));

        clearInvocations(refreshTokenGenerator);

        TransactionTemplate transactionTemplate =
                new TransactionTemplate(transactionManager);

        assertThatThrownBy(() ->
                transactionTemplate.executeWithoutResult(status -> {
                    assertThat(TransactionSynchronizationManager
                            .isActualTransactionActive())
                            .isTrue();

                    rotationService.rotate(rawToken);
                })
        ).isInstanceOf(
                IllegalTransactionStateException.class
        );

        verifyNoInteractions(refreshTokenGenerator);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(tokenHash))
                .isEqualTo(originalToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);
    }


    @Test
    void rotate_afterRejectedTransactionalInvocation_allowsNormalRotation() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(originalTokenHash);

        mutableClock.advance(Duration.ofDays(10));

        TransactionTemplate transactionTemplate =
                new TransactionTemplate(transactionManager);

        assertThatThrownBy(() ->
                transactionTemplate.executeWithoutResult(status ->
                        rotationService.rotate(originalRawToken)
                )
        ).isInstanceOf(
                IllegalTransactionStateException.class
        );

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(originalToken);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        mutableClock.advance(Duration.ofDays(1));

        Instant rotationTime = mutableClock.instant();

        RefreshTokenRotationResult rotationResult =
                rotationService.rotate(originalRawToken);

        String replacementTokenHash =
                refreshTokenGenerator.hash(
                        rotationResult.rawRefreshToken()
                );

        assertThat(rotationResult.userId())
                .isEqualTo(userId);

        assertThat(rotationResult.sessionId())
                .isEqualTo(sessionId);

        assertThat(rotationResult.rawRefreshToken())
                .isNotEqualTo(originalRawToken);

        assertThat(rotationResult.sessionExpiresAt())
                .isEqualTo(
                        issuanceResult.sessionExpiresAt()
                );

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isEqualTo(
                        rotationTime.plus(REFRESH_TOKEN_TTL)
                );

        Map<String, Object> consumedToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementToken =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                consumedToken,
                "consumed_at"
        )).isEqualTo(rotationTime);

        assertThat(replacementToken.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(readTimestamp(
                replacementToken,
                "created_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                replacementToken,
                "expires_at"
        )).isEqualTo(
                rotationResult.refreshTokenExpiresAt()
        );

        assertThat(readTimestamp(
                replacementToken,
                "consumed_at"
        )).isNull();

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }



}
