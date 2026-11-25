package com.ping.backend.entity;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.postgresql.util.PSQLException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
})
class AuthPersistenceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    private static final Instant CREATED_AT =
            Instant.parse("2025-01-01T00:00:00.123456Z");

    private static final Instant SESSION_EXPIRES_AT =
            CREATED_AT.plus(90, ChronoUnit.DAYS);

    private static final Instant TOKEN_EXPIRES_AT =
            CREATED_AT.plus(30, ChronoUnit.DAYS);

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private TransactionTemplate transactionTemplate;

    private final List<UUID> createdUserIds = new ArrayList<>();

    @BeforeEach
    void setUp() {
        transactionTemplate =
                new TransactionTemplate(transactionManager);
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

    private String generateTokenHash() {
        return UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
    }

    private AuthSession newSession(UUID userId) {
        return new AuthSession(
                UUID.randomUUID(),
                userId,
                CREATED_AT,
                SESSION_EXPIRES_AT
        );
    }

    private RefreshToken newRefreshToken(UUID sessionId) {
        return new RefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT
        );
    }

    private <T> T inTransaction(Supplier<T> operation) {
        return transactionTemplate.execute(
                status -> operation.get()
        );
    }

    private void inTransaction(Runnable operation) {
        transactionTemplate.executeWithoutResult(
                status -> operation.run()
        );
    }

    private UUID persistSession(UUID userId) {
        AuthSession session = newSession(userId);

        inTransaction(() -> {
            entityManager.persist(session);
            entityManager.flush();
        });

        return session.getId();
    }

    private UUID persistRefreshToken(UUID sessionId) {
        RefreshToken token = newRefreshToken(sessionId);

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        return token.getId();
    }

    private void assertUniqueConstraintViolation(
            Throwable thrown,
            String constraintName
    ) {
        assertThat(thrown)
                .hasRootCauseInstanceOf(PSQLException.class);

        Throwable rootCause = thrown;

        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }

        PSQLException sqlException = (PSQLException) rootCause;

        assertThat(sqlException.getSQLState())
                .isEqualTo("23505");

        assertThat(sqlException.getServerErrorMessage())
                .isNotNull();

        assertThat(sqlException.getServerErrorMessage().getConstraint())
                .isEqualTo(constraintName);
    }

    @Test
    void persistenceInfrastructure_initializesSuccessfully() {
        assertThat(postgres.isRunning()).isTrue();
        assertThat(entityManager).isNotNull();
        assertThat(jdbcClient).isNotNull();
        assertThat(transactionTemplate).isNotNull();

        Integer result = inTransaction(() -> {
            Number value = (Number) entityManager
                    .createNativeQuery("SELECT 1")
                    .getSingleResult();

            return value.intValue();
        });

        assertThat(result).isEqualTo(1);
    }

    @Test
    void persistSession_validEntity_persistsAllFields() {
        UUID userId = createUser();
        AuthSession session = newSession(userId);

        AuthSession persistedSession = inTransaction(() -> {
            entityManager.persist(session);
            entityManager.flush();
            entityManager.clear();

            return entityManager.find(
                    AuthSession.class,
                    session.getId()
            );
        });

        assertThat(persistedSession).isNotNull();
        assertThat(persistedSession).isNotSameAs(session);
        assertThat(persistedSession.getId())
                .isEqualTo(session.getId());
        assertThat(persistedSession.getUserId())
                .isEqualTo(userId);
        assertThat(persistedSession.getCreatedAt())
                .isEqualTo(CREATED_AT);
        assertThat(persistedSession.getExpiresAt())
                .isEqualTo(SESSION_EXPIRES_AT);
        assertThat(persistedSession.getRevokedAt()).isNull();
    }

    @Test
    void persistSession_validEntity_storesCorrectDatabaseValues() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        jdbcClient.sql("""
            SELECT id,
                   user_id,
                   created_at,
                   expires_at,
                   revoked_at,
                   last_used_at
            FROM auth_sessions
            WHERE id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query((rs, rowNum) -> {
                    assertThat(rs.getObject("id", UUID.class))
                            .isEqualTo(sessionId);

                    assertThat(rs.getObject("user_id", UUID.class))
                            .isEqualTo(userId);

                    assertThat(rs.getObject(
                            "created_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(CREATED_AT);

                    assertThat(rs.getObject(
                            "expires_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(SESSION_EXPIRES_AT);

                    assertThat(rs.getObject("revoked_at")).isNull();
                    assertThat(rs.getObject("last_used_at")).isNull();

                    return true;
                })
                .single();
    }

    @Test
    void persistSession_sameUser_allowsMultipleSessions() {
        UUID userId = createUser();

        UUID firstSessionId = persistSession(userId);
        UUID secondSessionId = persistSession(userId);

        assertThat(firstSessionId)
                .isNotEqualTo(secondSessionId);

        Long sessionCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(sessionCount).isEqualTo(2L);
    }

    @Test
    void revokeSession_managedEntity_persistsRevocation() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        Instant revokedAt = CREATED_AT.plusSeconds(60);

        inTransaction(() -> {
            AuthSession session = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            session.revoke(revokedAt);
            entityManager.flush();
        });

        AuthSession persistedSession = inTransaction(() -> {
            return entityManager.find(
                    AuthSession.class,
                    sessionId
            );
        });

        assertThat(persistedSession.isRevoked()).isTrue();
        assertThat(persistedSession.isActive(revokedAt)).isFalse();
        assertThat(persistedSession.getRevokedAt())
                .isEqualTo(revokedAt);
    }

    @Test
    void revokeSession_alreadyRevoked_preservesOriginalTimestamp() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        Instant firstRevokedAt = CREATED_AT.plusSeconds(60);
        Instant secondRevokedAt = CREATED_AT.plusSeconds(120);

        inTransaction(() -> {
            AuthSession session = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            session.revoke(firstRevokedAt);
            entityManager.flush();
        });

        inTransaction(() -> {
            AuthSession session = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            session.revoke(secondRevokedAt);
            entityManager.flush();
        });

        AuthSession persistedSession = inTransaction(() -> {
            return entityManager.find(
                    AuthSession.class,
                    sessionId
            );
        });

        assertThat(persistedSession.isRevoked()).isTrue();
        assertThat(persistedSession.getRevokedAt())
                .isEqualTo(firstRevokedAt);
    }

    @Test
    void reloadSession_expiredSession_preservesExpirationBehavior() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        AuthSession persistedSession = inTransaction(() -> {
            return entityManager.find(
                    AuthSession.class,
                    sessionId
            );
        });

        assertThat(persistedSession.getExpiresAt())
                .isEqualTo(SESSION_EXPIRES_AT);

        assertThat(persistedSession.isExpired(
                SESSION_EXPIRES_AT.minusNanos(1)
        )).isFalse();

        assertThat(persistedSession.isExpired(
                SESSION_EXPIRES_AT
        )).isTrue();

        assertThat(persistedSession.isExpired(
                SESSION_EXPIRES_AT.plusNanos(1)
        )).isTrue();

        assertThat(persistedSession.isActive(
                SESSION_EXPIRES_AT
        )).isFalse();

        assertThat(persistedSession.isRevoked()).isFalse();
    }

    @Test
    void persistRefreshToken_validEntity_persistsAllFields() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token = newRefreshToken(sessionId);

        RefreshToken persistedToken = inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
            entityManager.clear();

            return entityManager.find(
                    RefreshToken.class,
                    token.getId()
            );
        });

        assertThat(persistedToken).isNotNull();
        assertThat(persistedToken).isNotSameAs(token);
        assertThat(persistedToken.getId())
                .isEqualTo(token.getId());
        assertThat(persistedToken.getSessionId())
                .isEqualTo(sessionId);
        assertThat(persistedToken.getTokenHash())
                .isEqualTo(token.getTokenHash());
        assertThat(persistedToken.getCreatedAt())
                .isEqualTo(CREATED_AT);
        assertThat(persistedToken.getExpiresAt())
                .isEqualTo(TOKEN_EXPIRES_AT);
        assertThat(persistedToken.getConsumedAt()).isNull();
    }

    @Test
    void persistRefreshToken_validEntity_storesCorrectDatabaseValues() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token = newRefreshToken(sessionId);

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        jdbcClient.sql("""
            SELECT id,
                   session_id,
                   token_hash,
                   created_at,
                   expires_at,
                   consumed_at
            FROM auth_refresh_tokens
            WHERE id = :tokenId
            """)
                .param("tokenId", token.getId())
                .query((rs, rowNum) -> {
                    assertThat(rs.getObject("id", UUID.class))
                            .isEqualTo(token.getId());

                    assertThat(rs.getObject("session_id", UUID.class))
                            .isEqualTo(sessionId);

                    assertThat(rs.getString("token_hash"))
                            .isEqualTo(token.getTokenHash())
                            .hasSize(64)
                            .matches("[0-9a-f]{64}");

                    assertThat(rs.getObject(
                            "created_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(CREATED_AT);

                    assertThat(rs.getObject(
                            "expires_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(TOKEN_EXPIRES_AT);

                    assertThat(rs.getObject("consumed_at")).isNull();

                    return true;
                })
                .single();
    }

    @Test
    void persistRefreshToken_differentSessions_allowsUnconsumedTokens() {
        UUID userId = createUser();

        UUID firstSessionId = persistSession(userId);
        UUID secondSessionId = persistSession(userId);

        UUID firstTokenId = persistRefreshToken(firstSessionId);
        UUID secondTokenId = persistRefreshToken(secondSessionId);

        List<RefreshToken> tokens = inTransaction(() -> {
            RefreshToken firstToken = entityManager.find(
                    RefreshToken.class,
                    firstTokenId
            );

            RefreshToken secondToken = entityManager.find(
                    RefreshToken.class,
                    secondTokenId
            );

            return List.of(firstToken, secondToken);
        });

        assertThat(tokens).hasSize(2);

        RefreshToken firstToken = tokens.get(0);
        RefreshToken secondToken = tokens.get(1);

        assertThat(firstToken.getSessionId())
                .isEqualTo(firstSessionId);

        assertThat(secondToken.getSessionId())
                .isEqualTo(secondSessionId);

        assertThat(firstToken.getTokenHash())
                .isNotEqualTo(secondToken.getTokenHash());

        assertThat(firstToken.isConsumed()).isFalse();
        assertThat(secondToken.isConsumed()).isFalse();
    }

    @Test
    void consumeRefreshToken_managedEntity_persistsConsumption() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID tokenId = persistRefreshToken(sessionId);

        Instant consumedAt = CREATED_AT.plusSeconds(60);

        inTransaction(() -> {
            RefreshToken token = entityManager.find(
                    RefreshToken.class,
                    tokenId
            );

            token.consume(consumedAt);
            entityManager.flush();
        });

        RefreshToken persistedToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    tokenId
            );
        });

        assertThat(persistedToken.isConsumed()).isTrue();
        assertThat(persistedToken.getConsumedAt())
                .isEqualTo(consumedAt);
        assertThat(persistedToken.getSessionId())
                .isEqualTo(sessionId);
        assertThat(persistedToken.isExpired(consumedAt))
                .isFalse();
    }

    @Test
    void reloadRefreshToken_consumedToken_rejectsRepeatedConsumption() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID tokenId = persistRefreshToken(sessionId);

        Instant firstConsumedAt = CREATED_AT.plusSeconds(60);
        Instant secondConsumedAt = CREATED_AT.plusSeconds(120);

        inTransaction(() -> {
            RefreshToken token = entityManager.find(
                    RefreshToken.class,
                    tokenId
            );

            token.consume(firstConsumedAt);
            entityManager.flush();
        });

        assertThatThrownBy(() -> inTransaction(() -> {
            RefreshToken token = entityManager.find(
                    RefreshToken.class,
                    tokenId
            );

            token.consume(secondConsumedAt);
            entityManager.flush();
        }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Refresh token is not valid");

        RefreshToken persistedToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    tokenId
            );
        });

        assertThat(persistedToken.isConsumed()).isTrue();
        assertThat(persistedToken.getConsumedAt())
                .isEqualTo(firstConsumedAt);
    }

    @Test
    void reloadRefreshToken_expiredToken_preservesExpirationBehavior() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID tokenId = persistRefreshToken(sessionId);

        RefreshToken persistedToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    tokenId
            );
        });

        assertThat(persistedToken.getExpiresAt())
                .isEqualTo(TOKEN_EXPIRES_AT);

        assertThat(persistedToken.isExpired(
                TOKEN_EXPIRES_AT.minusNanos(1)
        )).isFalse();

        assertThat(persistedToken.isExpired(
                TOKEN_EXPIRES_AT
        )).isTrue();

        assertThat(persistedToken.isExpired(
                TOKEN_EXPIRES_AT.plusNanos(1)
        )).isTrue();

        assertThat(persistedToken.isConsumed()).isFalse();
        assertThat(persistedToken.getConsumedAt()).isNull();
    }

    @Test
    void reloadRefreshToken_consumedAndExpired_preservesBothStates() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID tokenId = persistRefreshToken(sessionId);

        Instant consumedAt = CREATED_AT.plusSeconds(60);
        Instant now = TOKEN_EXPIRES_AT.plusSeconds(1);

        inTransaction(() -> {
            RefreshToken token = entityManager.find(
                    RefreshToken.class,
                    tokenId
            );

            token.consume(consumedAt);
            entityManager.flush();
        });

        RefreshToken persistedToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    tokenId
            );
        });

        AuthSession persistedSession = inTransaction(() -> {
            return entityManager.find(
                    AuthSession.class,
                    sessionId
            );
        });

        assertThat(persistedToken.isConsumed()).isTrue();
        assertThat(persistedToken.isExpired(now)).isTrue();
        assertThat(persistedToken.getConsumedAt())
                .isEqualTo(consumedAt);

        assertThat(persistedSession.isActive(now)).isTrue();
    }

    @Test
    void rotateRefreshToken_validRotation_persistsBothTokens() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID oldTokenId = persistRefreshToken(sessionId);

        Instant rotationTime = CREATED_AT.plusSeconds(60);

        RefreshToken newToken = new RefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                rotationTime,
                rotationTime.plus(30, ChronoUnit.DAYS)
        );

        inTransaction(() -> {
            RefreshToken oldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            oldToken.consume(rotationTime);
            entityManager.flush();

            entityManager.persist(newToken);
            entityManager.flush();
        });

        inTransaction(() -> {
            RefreshToken persistedOldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            RefreshToken persistedNewToken = entityManager.find(
                    RefreshToken.class,
                    newToken.getId()
            );

            assertThat(persistedOldToken).isNotNull();
            assertThat(persistedNewToken).isNotNull();

            assertThat(persistedOldToken.isConsumed()).isTrue();
            assertThat(persistedOldToken.getConsumedAt())
                    .isEqualTo(rotationTime);

            assertThat(persistedNewToken.isConsumed()).isFalse();
            assertThat(persistedNewToken.getConsumedAt()).isNull();

            assertThat(persistedNewToken.getSessionId())
                    .isEqualTo(sessionId);

            assertThat(persistedNewToken.getTokenHash())
                    .isNotEqualTo(persistedOldToken.getTokenHash());

            assertThat(persistedNewToken.getCreatedAt())
                    .isEqualTo(rotationTime);

            assertThat(persistedNewToken.getExpiresAt())
                    .isEqualTo(newToken.getExpiresAt());
        });

        Long unconsumedCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
              AND consumed_at IS NULL
            """)
                .param("sessionId", sessionId)
                .query(Long.class)
                .single();

        assertThat(unconsumedCount).isEqualTo(1L);
    }

    @Test
    void persistRefreshToken_sameSession_rejectsSecondUnconsumedToken() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID firstTokenId = persistRefreshToken(sessionId);

        RefreshToken secondToken = newRefreshToken(sessionId);

        Throwable thrown = catchThrowable(() -> inTransaction(() -> {
            entityManager.persist(secondToken);
            entityManager.flush();
        }));

        assertThat(thrown)
                .hasRootCauseInstanceOf(PSQLException.class);

        Throwable rootCause = thrown;

        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }

        PSQLException sqlException = (PSQLException) rootCause;

        assertThat(sqlException.getSQLState())
                .isEqualTo("23505");

        assertThat(sqlException.getServerErrorMessage())
                .isNotNull();

        assertUniqueConstraintViolation(
                thrown,
                "uq_auth_refresh_tokens_unconsumed_session"
        );

        inTransaction(() -> {
            RefreshToken firstToken = entityManager.find(
                    RefreshToken.class,
                    firstTokenId
            );

            RefreshToken rejectedToken = entityManager.find(
                    RefreshToken.class,
                    secondToken.getId()
            );

            assertThat(firstToken).isNotNull();
            assertThat(firstToken.isConsumed()).isFalse();
            assertThat(rejectedToken).isNull();
        });
    }

    @Test
    void rotateRefreshToken_insertFails_rollsBackConsumption() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID oldTokenId = persistRefreshToken(sessionId);

        RefreshToken originalToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );
        });

        Instant rotationTime = CREATED_AT.plusSeconds(60);

        RefreshToken duplicateToken = new RefreshToken(
                UUID.randomUUID(),
                sessionId,
                originalToken.getTokenHash(),
                rotationTime,
                rotationTime.plus(30, ChronoUnit.DAYS)
        );

        Throwable thrown = catchThrowable(() -> inTransaction(() -> {
            RefreshToken oldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            oldToken.consume(rotationTime);
            entityManager.flush();

            entityManager.persist(duplicateToken);
            entityManager.flush();
        }));

        assertThat(thrown)
                .hasRootCauseInstanceOf(PSQLException.class);

        Throwable rootCause = thrown;

        while (rootCause.getCause() != null) {
            rootCause = rootCause.getCause();
        }

        PSQLException sqlException = (PSQLException) rootCause;

        assertThat(sqlException.getSQLState())
                .isEqualTo("23505");

        assertThat(sqlException.getServerErrorMessage())
                .isNotNull();

        assertUniqueConstraintViolation(
                thrown,
                "uq_auth_refresh_tokens_hash"
        );

        inTransaction(() -> {
            RefreshToken persistedOldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            RefreshToken rejectedToken = entityManager.find(
                    RefreshToken.class,
                    duplicateToken.getId()
            );

            AuthSession persistedSession = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            assertThat(persistedOldToken).isNotNull();
            assertThat(persistedOldToken.isConsumed()).isFalse();
            assertThat(persistedOldToken.getConsumedAt()).isNull();

            assertThat(rejectedToken).isNull();

            assertThat(persistedSession.isActive(rotationTime))
                    .isTrue();
        });

        Long tokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(Long.class)
                .single();

        assertThat(tokenCount).isEqualTo(1L);
    }

    @Test
    void revokeSession_existingTokens_preservesTokenHistory() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);
        UUID oldTokenId = persistRefreshToken(sessionId);

        Instant rotationTime = CREATED_AT.plusSeconds(60);
        Instant revokedAt = rotationTime.plusSeconds(60);

        RefreshToken newToken = new RefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                rotationTime,
                rotationTime.plus(30, ChronoUnit.DAYS)
        );

        inTransaction(() -> {
            RefreshToken oldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            oldToken.consume(rotationTime);
            entityManager.flush();

            entityManager.persist(newToken);
            entityManager.flush();
        });

        inTransaction(() -> {
            AuthSession session = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            session.revoke(revokedAt);
            entityManager.flush();
        });

        inTransaction(() -> {
            AuthSession persistedSession = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            RefreshToken persistedOldToken = entityManager.find(
                    RefreshToken.class,
                    oldTokenId
            );

            RefreshToken persistedNewToken = entityManager.find(
                    RefreshToken.class,
                    newToken.getId()
            );

            assertThat(persistedSession.isRevoked()).isTrue();
            assertThat(persistedSession.isActive(revokedAt)).isFalse();
            assertThat(persistedSession.getRevokedAt())
                    .isEqualTo(revokedAt);

            assertThat(persistedOldToken).isNotNull();
            assertThat(persistedOldToken.isConsumed()).isTrue();
            assertThat(persistedOldToken.getConsumedAt())
                    .isEqualTo(rotationTime);

            assertThat(persistedNewToken).isNotNull();
            assertThat(persistedNewToken.isConsumed()).isFalse();
            assertThat(persistedNewToken.getConsumedAt()).isNull();
        });

        Long tokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens
            WHERE session_id = :sessionId
            """)
                .param("sessionId", sessionId)
                .query(Long.class)
                .single();

        assertThat(tokenCount).isEqualTo(2L);
    }




}