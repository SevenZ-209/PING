package com.ping.backend.database;

import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import java.util.ArrayList;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
})
class AuthSchemaIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    private static final OffsetDateTime CREATED_AT =
            OffsetDateTime.parse("2025-01-01T00:00:00Z");

    private static final OffsetDateTime SESSION_EXPIRES_AT =
            CREATED_AT.plusDays(90);

    private static final OffsetDateTime TOKEN_EXPIRES_AT =
            CREATED_AT.plusDays(30);

    @Autowired
    private JdbcClient jdbcClient;

    private final List<UUID> createdUserIds = new ArrayList<>();

    private UUID createUser() {
        UUID id = UUID.randomUUID();

        jdbcClient.sql("""
            INSERT INTO users
                (id, email, password_hash, display_name)
            VALUES
                (:id, :email, :passwordHash, :displayName)
            """)
                .param("id", id)
                .param("email", id + "@example.com")
                .param("passwordHash", "test-hash")
                .param("displayName", "Test User")
                .update();

        createdUserIds.add(id);

        return id;
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

    private UUID createSession(UUID userId) {
        UUID sessionId = UUID.randomUUID();

        insertSession(
                sessionId,
                userId,
                CREATED_AT,
                SESSION_EXPIRES_AT,
                null
        );

        return sessionId;
    }

    private void insertSession(
            UUID sessionId,
            UUID userId,
            OffsetDateTime createdAt,
            OffsetDateTime expiresAt,
            OffsetDateTime revokedAt
    ) {
        jdbcClient.sql("""
                INSERT INTO auth_sessions
                    (id, user_id, created_at, expires_at, revoked_at)
                VALUES
                    (:id, :userId, :createdAt, :expiresAt, :revokedAt)
                """)
                .param("id", sessionId)
                .param("userId", userId)
                .param("createdAt", createdAt)
                .param("expiresAt", expiresAt)
                .param("revokedAt", revokedAt)
                .update();
    }

    private String generateTokenHash() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }

    private UUID createRefreshToken(UUID sessionId) {
        UUID tokenId = UUID.randomUUID();

        insertRefreshToken(
                tokenId,
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                null
        );

        return tokenId;
    }

    private void insertRefreshToken(
            UUID tokenId,
            UUID sessionId,
            String tokenHash,
            OffsetDateTime createdAt,
            OffsetDateTime expiresAt,
            OffsetDateTime consumedAt
    ) {
        jdbcClient.sql("""
                INSERT INTO auth_refresh_tokens
                    (id, session_id, token_hash,
                     created_at, expires_at, consumed_at)
                VALUES
                    (:id, :sessionId, :tokenHash,
                     :createdAt, :expiresAt, :consumedAt)
                """)
                .param("id", tokenId)
                .param("sessionId", sessionId)
                .param("tokenHash", tokenHash)
                .param("createdAt", createdAt)
                .param("expiresAt", expiresAt)
                .param("consumedAt", consumedAt)
                .update();
    }

    private void assertConstraintViolation(
            Runnable operation,
            String expectedSqlState,
            String expectedConstraint
    ) {
        Throwable throwable = catchThrowable(operation::run);

        assertThat(throwable)
                .isInstanceOf(DataIntegrityViolationException.class)
                .hasRootCauseInstanceOf(PSQLException.class);

        Throwable rootCause = throwable;

        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }

        PSQLException exception = (PSQLException) rootCause;

        assertThat(exception.getSQLState())
                .isEqualTo(expectedSqlState);

        assertThat(exception.getServerErrorMessage())
                .isNotNull();

        assertThat(exception.getServerErrorMessage().getConstraint())
                .isEqualTo(expectedConstraint);
    }

    private int countUnconsumedTokens(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("sessionId", sessionId)
                .query(Integer.class)
                .single();
    }

    private int countConsumedTokens(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
              AND consumed_at IS NOT NULL
            """)
                .param("sessionId", sessionId)
                .query(Integer.class)
                .single();
    }

    private int countSessions(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Integer.class)
                .single();
    }

    private int countRefreshTokens(UUID sessionId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(Integer.class)
                .single();
    }

    @Test
    void schema_appliesRequiredMigrations() {
        var versions = jdbcClient.sql("""
                SELECT version
                FROM flyway_schema_history
                WHERE success = true
                ORDER BY installed_rank
                """)
                .query(String.class)
                .list();

        assertThat(versions)
                .contains("1", "2", "3");
    }

    @Test
    void insertSession_validData_succeeds() {
        UUID userId = createUser();
        UUID sessionId = createSession(userId);

        Integer count = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE id = :sessionId
              AND user_id = :userId
              AND revoked_at IS NULL
            """)
                .param("sessionId", sessionId)
                .param("userId", userId)
                .query(Integer.class)
                .single();

        assertThat(count).isEqualTo(1);
    }

    @Test
    void insertSession_nonexistentUser_rejects() {
        assertConstraintViolation(
                () -> createSession(UUID.randomUUID()),
                "23503",
                "fk_auth_sessions_user"
        );
    }

    @Test
    void insertSession_duplicateId_rejects() {
        UUID userId = createUser();
        UUID sessionId = createSession(userId);

        assertConstraintViolation(
                () -> insertSession(
                        sessionId,
                        userId,
                        CREATED_AT,
                        SESSION_EXPIRES_AT,
                        null
                ),
                "23505",
                "auth_sessions_pkey"
        );
    }

    @Test
    void insertSession_expirationEqualsCreation_rejects() {
        UUID userId = createUser();

        assertConstraintViolation(
                () -> insertSession(
                        UUID.randomUUID(),
                        userId,
                        CREATED_AT,
                        CREATED_AT,
                        null
                ),
                "23514",
                "chk_auth_sessions_expiry"
        );
    }

    @Test
    void insertSession_expirationBeforeCreation_rejects() {
        UUID userId = createUser();

        assertConstraintViolation(
                () -> insertSession(
                        UUID.randomUUID(),
                        userId,
                        CREATED_AT,
                        CREATED_AT.minusSeconds(1),
                        null
                ),
                "23514",
                "chk_auth_sessions_expiry"
        );
    }

    @Test
    void insertSession_revocationBeforeCreation_rejects() {
        UUID userId = createUser();

        assertConstraintViolation(
                () -> insertSession(
                        UUID.randomUUID(),
                        userId,
                        CREATED_AT,
                        SESSION_EXPIRES_AT,
                        CREATED_AT.minusSeconds(1)
                ),
                "23514",
                "chk_auth_sessions_revocation"
        );
    }

    @Test
    void insertSession_revocationEqualsCreation_succeeds() {
        UUID userId = createUser();
        UUID sessionId = UUID.randomUUID();

        insertSession(
                sessionId,
                userId,
                CREATED_AT,
                SESSION_EXPIRES_AT,
                CREATED_AT
        );

        OffsetDateTime revokedAt = jdbcClient.sql("""
            SELECT revoked_at
            FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(revokedAt).isEqualTo(CREATED_AT);
    }

    @Test
    void insertSession_revocationAfterCreation_succeeds() {
        UUID userId = createUser();
        UUID sessionId = UUID.randomUUID();
        OffsetDateTime expectedRevokedAt = CREATED_AT.plusDays(1);

        insertSession(
                sessionId,
                userId,
                CREATED_AT,
                SESSION_EXPIRES_AT,
                expectedRevokedAt
        );

        OffsetDateTime revokedAt = jdbcClient.sql("""
            SELECT revoked_at
            FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(revokedAt).isEqualTo(expectedRevokedAt);
    }

    @Test
    void insertRefreshToken_validData_succeeds() {
        UUID userId = createUser();
        UUID sessionId = createSession(userId);
        UUID tokenId = createRefreshToken(sessionId);

        Integer count = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE id = :tokenId
              AND session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("tokenId", tokenId)
                .param("sessionId", sessionId)
                .query(Integer.class)
                .single();

        assertThat(count).isEqualTo(1);
    }

    @Test
    void insertRefreshToken_nonexistentSession_rejects() {
        assertConstraintViolation(
                () -> createRefreshToken(UUID.randomUUID()),
                "23503",
                "fk_auth_refresh_tokens_session"
        );
    }

    @Test
    void insertRefreshToken_duplicateId_rejects() {
        UUID userId = createUser();
        UUID firstSessionId = createSession(userId);
        UUID secondSessionId = createSession(userId);
        UUID tokenId = createRefreshToken(firstSessionId);

        assertConstraintViolation(
                () -> insertRefreshToken(
                        tokenId,
                        secondSessionId,
                        generateTokenHash(),
                        CREATED_AT,
                        TOKEN_EXPIRES_AT,
                        null
                ),
                "23505",
                "auth_refresh_tokens_pkey"
        );
    }

    @Test
    void insertRefreshToken_duplicateHash_rejects() {
        UUID userId = createUser();
        UUID firstSessionId = createSession(userId);
        UUID secondSessionId = createSession(userId);
        String tokenHash = generateTokenHash();

        insertRefreshToken(
                UUID.randomUUID(),
                firstSessionId,
                tokenHash,
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                null
        );

        assertConstraintViolation(
                () -> insertRefreshToken(
                        UUID.randomUUID(),
                        secondSessionId,
                        tokenHash,
                        CREATED_AT,
                        TOKEN_EXPIRES_AT,
                        null
                ),
                "23505",
                "uq_auth_refresh_tokens_hash"
        );
    }

    @Test
    void insertRefreshToken_expirationEqualsCreation_rejects() {
        UUID sessionId = createSession(createUser());

        assertConstraintViolation(
                () -> insertRefreshToken(
                        UUID.randomUUID(),
                        sessionId,
                        generateTokenHash(),
                        CREATED_AT,
                        CREATED_AT,
                        null
                ),
                "23514",
                "chk_auth_refresh_tokens_expiry"
        );
    }

    @Test
    void insertRefreshToken_expirationBeforeCreation_rejects() {
        UUID sessionId = createSession(createUser());

        assertConstraintViolation(
                () -> insertRefreshToken(
                        UUID.randomUUID(),
                        sessionId,
                        generateTokenHash(),
                        CREATED_AT,
                        CREATED_AT.minusSeconds(1),
                        null
                ),
                "23514",
                "chk_auth_refresh_tokens_expiry"
        );
    }
    @Test
    void insertRefreshToken_consumptionBeforeCreation_rejects() {
        UUID sessionId = createSession(createUser());

        assertConstraintViolation(
                () -> insertRefreshToken(
                        UUID.randomUUID(),
                        sessionId,
                        generateTokenHash(),
                        CREATED_AT,
                        TOKEN_EXPIRES_AT,
                        CREATED_AT.minusSeconds(1)
                ),
                "23514",
                "chk_auth_refresh_tokens_consumption"
        );
    }

    @Test
    void insertRefreshToken_consumptionEqualsCreation_succeeds() {
        UUID sessionId = createSession(createUser());
        UUID tokenId = UUID.randomUUID();

        insertRefreshToken(
                tokenId,
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                CREATED_AT
        );

        OffsetDateTime consumedAt = jdbcClient.sql("""
            SELECT consumed_at
            FROM auth_refresh_tokens
            WHERE id = :tokenId
            """)
                .param("tokenId", tokenId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(consumedAt).isEqualTo(CREATED_AT);
    }

    @Test
    void insertRefreshToken_consumptionAfterCreation_succeeds() {
        UUID sessionId = createSession(createUser());
        UUID tokenId = UUID.randomUUID();
        OffsetDateTime expectedConsumedAt = CREATED_AT.plusDays(1);

        insertRefreshToken(
                tokenId,
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                expectedConsumedAt
        );

        OffsetDateTime consumedAt = jdbcClient.sql("""
            SELECT consumed_at
            FROM auth_refresh_tokens
            WHERE id = :tokenId
            """)
                .param("tokenId", tokenId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(consumedAt).isEqualTo(expectedConsumedAt);
    }

    @Test
    void insertRefreshToken_secondUnconsumedInSameSession_rejects() {
        UUID sessionId = createSession(createUser());

        createRefreshToken(sessionId);

        assertConstraintViolation(
                () -> createRefreshToken(sessionId),
                "23505",
                "uq_auth_refresh_tokens_unconsumed_session"
        );

        assertThat(countUnconsumedTokens(sessionId)).isEqualTo(1);
    }

    @Test
    void insertRefreshToken_unconsumedInDifferentSessions_succeeds() {
        UUID userId = createUser();

        UUID firstSessionId = createSession(userId);
        UUID secondSessionId = createSession(userId);

        createRefreshToken(firstSessionId);
        createRefreshToken(secondSessionId);

        assertThat(countUnconsumedTokens(firstSessionId))
                .isEqualTo(1);

        assertThat(countUnconsumedTokens(secondSessionId))
                .isEqualTo(1);
    }

    @Test
    void insertRefreshToken_multipleConsumedInSameSession_succeeds() {
        UUID sessionId = createSession(createUser());

        for (int i = 0; i < 3; i++) {
            insertRefreshToken(
                    UUID.randomUUID(),
                    sessionId,
                    generateTokenHash(),
                    CREATED_AT,
                    TOKEN_EXPIRES_AT,
                    CREATED_AT.plusDays(i + 1)
            );
        }

        assertThat(countConsumedTokens(sessionId)).isEqualTo(3);
        assertThat(countUnconsumedTokens(sessionId)).isZero();
    }

    @Test
    void rotateRefreshToken_consumeBeforeInsert_succeeds() {
        UUID sessionId = createSession(createUser());
        UUID oldTokenId = createRefreshToken(sessionId);

        OffsetDateTime rotationTime = CREATED_AT.plusDays(1);

        int updatedRows = jdbcClient.sql("""
            UPDATE auth_refresh_tokens
            SET consumed_at = :consumedAt
            WHERE id = :tokenId
              AND consumed_at IS NULL
            """)
                .param("consumedAt", rotationTime)
                .param("tokenId", oldTokenId)
                .update();

        assertThat(updatedRows).isEqualTo(1);

        UUID newTokenId = UUID.randomUUID();

        insertRefreshToken(
                newTokenId,
                sessionId,
                generateTokenHash(),
                rotationTime,
                rotationTime.plusDays(30),
                null
        );

        assertThat(countConsumedTokens(sessionId)).isEqualTo(1);
        assertThat(countUnconsumedTokens(sessionId)).isEqualTo(1);

        Integer count = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE id = :tokenId
              AND session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("tokenId", newTokenId)
                .param("sessionId", sessionId)
                .query(Integer.class)
                .single();

        assertThat(count).isEqualTo(1);
    }

    @Test
    void insertRefreshToken_existingExpiredUnconsumedToken_rejects() {
        UUID userId = createUser();

        OffsetDateTime now = OffsetDateTime.now()
                .withNano(0);

        UUID sessionId = UUID.randomUUID();

        insertSession(
                sessionId,
                userId,
                now.minusDays(31),
                now.plusDays(59),
                null
        );

        insertRefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                now.minusDays(31),
                now.minusDays(1),
                null
        );

        assertConstraintViolation(
                () -> insertRefreshToken(
                        UUID.randomUUID(),
                        sessionId,
                        generateTokenHash(),
                        now,
                        now.plusDays(30),
                        null
                ),
                "23505",
                "uq_auth_refresh_tokens_unconsumed_session"
        );

        assertThat(countUnconsumedTokens(sessionId)).isEqualTo(1);
    }

    @Test
    void deleteSession_cascadesRefreshTokens() {
        UUID userId = createUser();
        UUID sessionId = createSession(userId);

        insertRefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                CREATED_AT.plusDays(1)
        );

        createRefreshToken(sessionId);

        assertThat(countRefreshTokens(sessionId)).isEqualTo(2);
        assertThat(countSessions(userId)).isEqualTo(1);

        int deletedRows = jdbcClient.sql("""
            DELETE FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .update();

        assertThat(deletedRows).isEqualTo(1);
        assertThat(countRefreshTokens(sessionId)).isZero();
        assertThat(countSessions(userId)).isZero();

        Integer userCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM users
            WHERE id = :userId
            """)
                .param("userId", userId)
                .query(Integer.class)
                .single();

        assertThat(userCount).isEqualTo(1);
    }

    @Test
    void deleteUser_cascadesSessionsAndRefreshTokens() {
        UUID userId = createUser();

        UUID firstSessionId = createSession(userId);
        UUID secondSessionId = createSession(userId);

        createRefreshToken(firstSessionId);
        createRefreshToken(secondSessionId);

        insertRefreshToken(
                UUID.randomUUID(),
                firstSessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT,
                CREATED_AT.plusDays(1)
        );

        assertThat(countSessions(userId)).isEqualTo(2);
        assertThat(countRefreshTokens(firstSessionId)).isEqualTo(2);
        assertThat(countRefreshTokens(secondSessionId)).isEqualTo(1);

        int deletedRows = jdbcClient.sql("""
            DELETE FROM users
            WHERE id = :userId
            """)
                .param("userId", userId)
                .update();

        assertThat(deletedRows).isEqualTo(1);
        assertThat(countSessions(userId)).isZero();
        assertThat(countRefreshTokens(firstSessionId)).isZero();
        assertThat(countRefreshTokens(secondSessionId)).isZero();
    }

    @Test
    void deleteSession_doesNotAffectOtherSessions() {
        UUID userId = createUser();

        UUID firstSessionId = createSession(userId);
        UUID secondSessionId = createSession(userId);

        createRefreshToken(firstSessionId);
        UUID secondTokenId = createRefreshToken(secondSessionId);

        assertThat(countSessions(userId)).isEqualTo(2);
        assertThat(countRefreshTokens(firstSessionId)).isEqualTo(1);
        assertThat(countRefreshTokens(secondSessionId)).isEqualTo(1);

        int deletedRows = jdbcClient.sql("""
            DELETE FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", firstSessionId)
                .update();

        assertThat(deletedRows).isEqualTo(1);
        assertThat(countSessions(userId)).isEqualTo(1);
        assertThat(countRefreshTokens(firstSessionId)).isZero();
        assertThat(countRefreshTokens(secondSessionId)).isEqualTo(1);

        Integer remainingTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE id = :tokenId
              AND session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("tokenId", secondTokenId)
                .param("sessionId", secondSessionId)
                .query(Integer.class)
                .single();

        assertThat(remainingTokenCount).isEqualTo(1);
    }

}