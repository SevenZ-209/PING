
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import com.ping.backend.validation.RefreshTokenValidator;
import org.junit.jupiter.api.AfterEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.containers.PostgreSQLContainer;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import java.time.OffsetDateTime;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.core.NestedExceptionUtils;
import java.sql.SQLException;

import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.doReturn;

import static org.assertj.core.api.Assertions.assertThatCode;

import static org.assertj.core.api.Assertions.assertThat;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
})
@Import(RefreshTokenIssuanceServiceIntegrationTest.ClockConfiguration.class)
class RefreshTokenIssuanceServiceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    private static final Instant CURRENT_TIME =
            Instant.parse("2026-01-01T00:00:00.123456789Z");

    private static final Instant EXPECTED_CREATED_AT =
            Instant.parse("2026-01-01T00:00:00.123456Z");

    @TestConfiguration(proxyBeanMethods = false)
    static class ClockConfiguration {

        @Bean
        @Primary
        Clock fixedTestClock() {
            return Clock.fixed(
                    CURRENT_TIME,
                    ZoneOffset.UTC
            );
        }
    }


    private Map<String, Object> findPersistedSession(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT id, user_id, created_at, expires_at, revoked_at
            FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query()
                .singleRow();
    }



    private Map<String, Object> findPersistedRefreshToken(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT id, session_id, token_hash,
                   created_at, expires_at, consumed_at
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query()
                .singleRow();
    }


    private Instant readTimestamp(
            Map<String, Object> row,
            String column
    ) {
        Object value = row.get(column);

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



    @Autowired
    private RefreshTokenIssuanceService issuanceService;

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
    private Clock clock;

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

    private long countSessionsByUserId(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }


    private long countRefreshTokensByUserId(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens token
            JOIN auth_sessions session
                ON token.session_id = session.id
            WHERE session.user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }


    private void assertSqlState(
            Throwable exception,
            String expectedSqlState
    ) {
        assertThat(exception)
                .isInstanceOf(DataIntegrityViolationException.class);

        Throwable rootCause =
                NestedExceptionUtils.getMostSpecificCause(
                        exception
                );

        assertThat(rootCause)
                .isInstanceOf(SQLException.class);

        SQLException sqlException =
                (SQLException) rootCause;

        assertThat(sqlException.getSQLState())
                .isEqualTo(expectedSqlState);
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



    @Test
    void issuanceInfrastructure_initializesSuccessfully() {
        assertThat(postgres.isRunning()).isTrue();

        assertThat(issuanceService).isNotNull();
        assertThat(authSessionRepository).isNotNull();
        assertThat(refreshTokenRepository).isNotNull();
        assertThat(refreshTokenGenerator).isNotNull();
        assertThat(refreshTokenValidator).isNotNull();
        assertThat(authProperties).isNotNull();
        assertThat(jdbcClient).isNotNull();
        assertThat(clock).isNotNull();

        assertThat(clock.instant())
                .isEqualTo(CURRENT_TIME);

        Integer result = jdbcClient.sql("SELECT 1")
                .query(Integer.class)
                .single();

        assertThat(result).isEqualTo(1);
    }

    @Test
    void issuanceService_isTransactionProxied() {
        assertThat(AopUtils.isAopProxy(issuanceService))
                .isTrue();

        assertThat(AopUtils.getTargetClass(issuanceService))
                .isEqualTo(RefreshTokenIssuanceService.class);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void issue_persistsSessionInDatabase() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Long sessionCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(sessionCount).isEqualTo(1L);

        Map<String, Object> session =
                findPersistedSession(result.sessionId());

        assertThat(session.get("id"))
                .isEqualTo(result.sessionId());

        assertThat(session.get("user_id"))
                .isEqualTo(userId);
    }


    @Test
    void issue_persistsRefreshTokenInDatabase() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Long tokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", result.sessionId())
                .query(Long.class)
                .single();

        assertThat(tokenCount).isEqualTo(1L);

        Map<String, Object> refreshToken =
                findPersistedRefreshToken(result.sessionId());

        assertThat(refreshToken.get("id"))
                .isInstanceOf(UUID.class);

        assertThat(refreshToken.get("session_id"))
                .isEqualTo(result.sessionId());
    }


    @Test
    void issue_persistsCorrectSessionFieldValues() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Map<String, Object> session =
                findPersistedSession(result.sessionId());

        assertThat(session.get("id"))
                .isEqualTo(result.sessionId());

        assertThat(session.get("user_id"))
                .isEqualTo(userId);

        assertThat(readTimestamp(session, "created_at"))
                .isEqualTo(EXPECTED_CREATED_AT);

        assertThat(readTimestamp(session, "expires_at"))
                .isEqualTo(
                        EXPECTED_CREATED_AT.plus(
                                authProperties.sessionTtl()
                        )
                );

        assertThat(session.get("revoked_at"))
                .isNull();
    }


    @Test
    void issue_persistsCorrectRefreshTokenFieldValues() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Map<String, Object> refreshToken =
                findPersistedRefreshToken(result.sessionId());

        assertThat(refreshToken.get("id"))
                .isInstanceOf(UUID.class)
                .isNotEqualTo(result.sessionId());

        assertThat(refreshToken.get("session_id"))
                .isEqualTo(result.sessionId());

        assertThat((String) refreshToken.get("token_hash"))
                .matches("[0-9a-f]{64}");

        assertThat(readTimestamp(refreshToken, "created_at"))
                .isEqualTo(EXPECTED_CREATED_AT);

        assertThat(readTimestamp(refreshToken, "expires_at"))
                .isEqualTo(
                        EXPECTED_CREATED_AT.plus(
                                authProperties.refreshTokenTtl()
                        )
                );

        assertThat(refreshToken.get("consumed_at"))
                .isNull();
    }


    @Test
    void issue_resultTimestampsMatchPersistedTimestamps() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Map<String, Object> session =
                findPersistedSession(result.sessionId());

        Map<String, Object> refreshToken =
                findPersistedRefreshToken(result.sessionId());

        assertThat(result.sessionExpiresAt())
                .isEqualTo(
                        readTimestamp(session, "expires_at")
                );

        assertThat(result.refreshTokenExpiresAt())
                .isEqualTo(
                        readTimestamp(refreshToken, "expires_at")
                );

        assertThat(readTimestamp(session, "created_at"))
                .isEqualTo(
                        readTimestamp(refreshToken, "created_at")
                );

        assertThat(result.refreshTokenExpiresAt())
                .isBeforeOrEqualTo(result.sessionExpiresAt());
    }


    @Test
    void issue_generatesValidRawRefreshToken() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        String rawRefreshToken = result.rawRefreshToken();

        assertThat(rawRefreshToken)
                .isNotNull()
                .hasSize(43)
                .matches("[A-Za-z0-9_-]{43}");

        assertThatCode(() ->
                refreshTokenValidator.validate(rawRefreshToken)
        ).doesNotThrowAnyException();
    }


    @Test
    void issue_persistedHashMatchesReturnedRawToken()
            throws NoSuchAlgorithmException {

        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Map<String, Object> refreshToken =
                findPersistedRefreshToken(result.sessionId());

        byte[] digest = MessageDigest
                .getInstance("SHA-256")
                .digest(
                        result.rawRefreshToken()
                                .getBytes(StandardCharsets.UTF_8)
                );

        String expectedHash =
                HexFormat.of().formatHex(digest);

        assertThat((String) refreshToken.get("token_hash"))
                .isEqualTo(expectedHash)
                .hasSize(64)
                .matches("[0-9a-f]{64}");
    }


    @Test
    void issue_doesNotPersistRawRefreshTokenInHashColumn() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult result =
                issuanceService.issue(userId);

        Map<String, Object> refreshToken =
                findPersistedRefreshToken(result.sessionId());

        String persistedHash =
                (String) refreshToken.get("token_hash");

        assertThat(persistedHash)
                .isNotNull()
                .isNotEqualTo(result.rawRefreshToken())
                .hasSize(64);

        Long rawTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE token_hash = :rawToken
            """)
                .param("rawToken", result.rawRefreshToken())
                .query(Long.class)
                .single();

        assertThat(rawTokenCount).isZero();
    }


    @Test
    void issue_sameUserReceivesMultipleIndependentSessions() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult firstResult =
                issuanceService.issue(userId);

        RefreshTokenIssuanceResult secondResult =
                issuanceService.issue(userId);

        assertThat(firstResult.sessionId())
                .isNotEqualTo(secondResult.sessionId());

        assertThat(firstResult.rawRefreshToken())
                .isNotEqualTo(secondResult.rawRefreshToken());

        Long sessionCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(sessionCount).isEqualTo(2L);

        Map<String, Object> firstSession =
                findPersistedSession(firstResult.sessionId());

        Map<String, Object> secondSession =
                findPersistedSession(secondResult.sessionId());

        assertThat(firstSession.get("user_id"))
                .isEqualTo(userId);

        assertThat(secondSession.get("user_id"))
                .isEqualTo(userId);

        assertThat(firstSession.get("revoked_at"))
                .isNull();

        assertThat(secondSession.get("revoked_at"))
                .isNull();

        Map<String, Object> firstToken =
                findPersistedRefreshToken(firstResult.sessionId());

        Map<String, Object> secondToken =
                findPersistedRefreshToken(secondResult.sessionId());

        assertThat(firstToken.get("id"))
                .isNotEqualTo(secondToken.get("id"));

        assertThat(firstToken.get("token_hash"))
                .isNotEqualTo(secondToken.get("token_hash"));

        assertThat(firstToken.get("session_id"))
                .isEqualTo(firstResult.sessionId());

        assertThat(secondToken.get("session_id"))
                .isEqualTo(secondResult.sessionId());

        assertThat(firstToken.get("consumed_at"))
                .isNull();

        assertThat(secondToken.get("consumed_at"))
                .isNull();
    }


    @Test
    void issue_eachNewSessionHasExactlyOneUnconsumedToken() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult firstResult =
                issuanceService.issue(userId);

        RefreshTokenIssuanceResult secondResult =
                issuanceService.issue(userId);

        Long firstTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", firstResult.sessionId())
                .query(Long.class)
                .single();

        Long secondTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", secondResult.sessionId())
                .query(Long.class)
                .single();

        Long unconsumedTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens token
            JOIN auth_sessions session
                ON token.session_id = session.id
            WHERE session.user_id = :userId
              AND token.consumed_at IS NULL
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(firstTokenCount).isEqualTo(1L);

        assertThat(secondTokenCount).isEqualTo(1L);

        assertThat(unconsumedTokenCount).isEqualTo(2L);

        assertThat(
                findPersistedRefreshToken(
                        firstResult.sessionId()
                ).get("consumed_at")
        ).isNull();

        assertThat(
                findPersistedRefreshToken(
                        secondResult.sessionId()
                ).get("consumed_at")
        ).isNull();
    }


    @Test
    void issue_withNonexistentUserId_failsForeignKeyConstraint() {
        UUID nonexistentUserId = UUID.randomUUID();

        assertThat(countSessionsByUserId(nonexistentUserId))
                .isZero();

        Throwable exception = catchThrowable(() ->
                issuanceService.issue(nonexistentUserId)
        );

        assertSqlState(exception, "23503");

        assertThat(countSessionsByUserId(nonexistentUserId))
                .isZero();

        assertThat(countRefreshTokensByUserId(nonexistentUserId))
                .isZero();

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void issue_withDuplicateTokenHash_rollsBackNewSession() {
        UUID existingUserId = createUser();
        UUID newUserId = createUser();

        RefreshTokenIssuanceResult existingResult =
                issuanceService.issue(existingUserId);

        assertThat(countSessionsByUserId(existingUserId))
                .isEqualTo(1L);

        assertThat(countSessionsByUserId(newUserId))
                .isZero();

        assertThat(countRefreshTokensByUserId(newUserId))
                .isZero();

        doReturn(existingResult.rawRefreshToken())
                .when(refreshTokenGenerator)
                .generate();

        Throwable exception = catchThrowable(() ->
                issuanceService.issue(newUserId)
        );

        assertSqlState(exception, "23505");

        assertThat(countSessionsByUserId(newUserId))
                .isZero();

        assertThat(countRefreshTokensByUserId(newUserId))
                .isZero();

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive())
                .isFalse();
    }


    @Test
    void issue_whenPersistenceFails_preservesExistingData() {
        UUID existingUserId = createUser();
        UUID newUserId = createUser();

        RefreshTokenIssuanceResult existingResult =
                issuanceService.issue(existingUserId);

        Map<String, Object> sessionBefore =
                findPersistedSession(
                        existingResult.sessionId()
                );

        Map<String, Object> tokenBefore =
                findPersistedRefreshToken(
                        existingResult.sessionId()
                );

        doReturn(existingResult.rawRefreshToken())
                .when(refreshTokenGenerator)
                .generate();

        Throwable exception = catchThrowable(() ->
                issuanceService.issue(newUserId)
        );

        assertSqlState(exception, "23505");

        Map<String, Object> sessionAfter =
                findPersistedSession(
                        existingResult.sessionId()
                );

        Map<String, Object> tokenAfter =
                findPersistedRefreshToken(
                        existingResult.sessionId()
                );

        assertThat(sessionAfter)
                .isEqualTo(sessionBefore);

        assertThat(tokenAfter)
                .isEqualTo(tokenBefore);

        assertThat(countSessionsByUserId(existingUserId))
                .isEqualTo(1L);

        assertThat(countRefreshTokensByUserId(existingUserId))
                .isEqualTo(1L);

        assertThat(sessionAfter.get("revoked_at"))
                .isNull();

        assertThat(tokenAfter.get("consumed_at"))
                .isNull();

        assertThat(countSessionsByUserId(newUserId))
                .isZero();

        assertThat(countRefreshTokensByUserId(newUserId))
                .isZero();
    }



}
