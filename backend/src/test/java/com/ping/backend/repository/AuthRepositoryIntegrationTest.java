package com.ping.backend.repository;

import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import org.hibernate.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
})
class AuthRepositoryIntegrationTest {

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
    private AuthSessionRepository authSessionRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

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

    private RefreshToken persistRefreshToken(UUID sessionId) {
        RefreshToken token = newRefreshToken(sessionId);

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        return token;
    }

    @Test
    void repositoryInfrastructure_initializesSuccessfully() {
        assertThat(postgres.isRunning()).isTrue();
        assertThat(entityManager).isNotNull();
        assertThat(jdbcClient).isNotNull();
        assertThat(authSessionRepository).isNotNull();
        assertThat(refreshTokenRepository).isNotNull();
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
    void saveSession_validEntity_persistsAllFields() {
        UUID userId = createUser();
        AuthSession session = newSession(userId);

        AuthSession savedSession = inTransaction(() -> {
            AuthSession saved = authSessionRepository.save(session);
            authSessionRepository.flush();

            assertThat(entityManager.contains(saved)).isTrue();

            return saved;
        });

        AuthSession reloadedSession = inTransaction(() -> {
            return entityManager.find(
                    AuthSession.class,
                    savedSession.getId()
            );
        });

        assertThat(reloadedSession).isNotNull();
        assertThat(reloadedSession).isNotSameAs(savedSession);

        assertThat(reloadedSession.getId())
                .isEqualTo(session.getId());

        assertThat(reloadedSession.getUserId())
                .isEqualTo(userId);

        assertThat(reloadedSession.getCreatedAt())
                .isEqualTo(CREATED_AT);

        assertThat(reloadedSession.getExpiresAt())
                .isEqualTo(SESSION_EXPIRES_AT);

        assertThat(reloadedSession.getRevokedAt()).isNull();
    }

    @Test
    void saveRefreshToken_validEntity_persistsAllFields() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token = newRefreshToken(sessionId);

        RefreshToken savedToken = inTransaction(() -> {
            RefreshToken saved = refreshTokenRepository.save(token);
            refreshTokenRepository.flush();

            assertThat(entityManager.contains(saved)).isTrue();

            return saved;
        });

        RefreshToken reloadedToken = inTransaction(() -> {
            return entityManager.find(
                    RefreshToken.class,
                    savedToken.getId()
            );
        });

        assertThat(reloadedToken).isNotNull();
        assertThat(reloadedToken).isNotSameAs(savedToken);

        assertThat(reloadedToken.getId())
                .isEqualTo(token.getId());

        assertThat(reloadedToken.getSessionId())
                .isEqualTo(sessionId);

        assertThat(reloadedToken.getTokenHash())
                .isEqualTo(token.getTokenHash());

        assertThat(reloadedToken.getCreatedAt())
                .isEqualTo(CREATED_AT);

        assertThat(reloadedToken.getExpiresAt())
                .isEqualTo(TOKEN_EXPIRES_AT);

        assertThat(reloadedToken.getConsumedAt()).isNull();
    }

    @Test
    void findByIdForUpdate_existingSession_returnsLockedSession() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        inTransaction(() -> {
            Optional<AuthSession> result =
                    authSessionRepository.findByIdForUpdate(sessionId);

            assertThat(result).isPresent();

            AuthSession session = result.orElseThrow();

            assertThat(session.getId())
                    .isEqualTo(sessionId);

            assertThat(session.getUserId())
                    .isEqualTo(userId);

            assertThat(session.getCreatedAt())
                    .isEqualTo(CREATED_AT);

            assertThat(session.getExpiresAt())
                    .isEqualTo(SESSION_EXPIRES_AT);

            assertThat(session.getRevokedAt()).isNull();

            assertThat(entityManager.contains(session))
                    .isTrue();

            assertThat(entityManager.getLockMode(session))
                    .isEqualTo(LockModeType.PESSIMISTIC_WRITE);
        });
    }

    @Test
    void findByIdForUpdate_nonexistentSession_returnsEmpty() {
        UUID nonexistentSessionId = UUID.randomUUID();

        Optional<AuthSession> result = inTransaction(() -> {
            return authSessionRepository.findByIdForUpdate(
                    nonexistentSessionId
            );
        });

        assertThat(result).isEmpty();
    }

    @Test
    void findByIdForUpdate_revokedSession_returnsLockedSession() {
        UUID userId = createUser();
        AuthSession session = newSession(userId);

        Instant revokedAt = CREATED_AT.plusSeconds(60);

        session.revoke(revokedAt);

        inTransaction(() -> {
            entityManager.persist(session);
            entityManager.flush();
        });

        inTransaction(() -> {
            Optional<AuthSession> result =
                    authSessionRepository.findByIdForUpdate(
                            session.getId()
                    );

            assertThat(result).isPresent();

            AuthSession lockedSession = result.orElseThrow();

            assertThat(lockedSession.getId())
                    .isEqualTo(session.getId());

            assertThat(lockedSession.isRevoked()).isTrue();

            assertThat(lockedSession.getRevokedAt())
                    .isEqualTo(revokedAt);

            assertThat(lockedSession.isActive(revokedAt))
                    .isFalse();

            assertThat(entityManager.getLockMode(lockedSession))
                    .isEqualTo(LockModeType.PESSIMISTIC_WRITE);
        });
    }

    @Test
    void findByIdForUpdate_expiredSession_returnsLockedSession() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        Instant now = SESSION_EXPIRES_AT.plusSeconds(1);

        inTransaction(() -> {
            Optional<AuthSession> result =
                    authSessionRepository.findByIdForUpdate(sessionId);

            assertThat(result).isPresent();

            AuthSession session = result.orElseThrow();

            assertThat(session.getId())
                    .isEqualTo(sessionId);

            assertThat(session.isExpired(now)).isTrue();
            assertThat(session.isRevoked()).isFalse();
            assertThat(session.isActive(now)).isFalse();

            assertThat(entityManager.getLockMode(session))
                    .isEqualTo(LockModeType.PESSIMISTIC_WRITE);
        });
    }

    @Test
    void findByIdForUpdate_nullSessionId_throwsNullPointerException() {
        assertThatThrownBy(() -> inTransaction(() -> {
            authSessionRepository.findByIdForUpdate(null);
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("sessionId is required");
    }

    @Test
    void findSessionIdByTokenHash_knownHash_returnsCorrectSessionId() {
        UUID userId = createUser();

        UUID firstSessionId = persistSession(userId);
        UUID secondSessionId = persistSession(userId);

        RefreshToken firstToken =
                persistRefreshToken(firstSessionId);

        RefreshToken secondToken =
                persistRefreshToken(secondSessionId);

        inTransaction(() -> {
            Session hibernateSession =
                    entityManager.unwrap(Session.class);

            assertThat(hibernateSession.getStatistics()
                    .getEntityCount()).isZero();

            Optional<UUID> firstResult =
                    refreshTokenRepository.findSessionIdByTokenHash(
                            firstToken.getTokenHash()
                    );

            Optional<UUID> secondResult =
                    refreshTokenRepository.findSessionIdByTokenHash(
                            secondToken.getTokenHash()
                    );

            assertThat(firstResult).contains(firstSessionId);
            assertThat(secondResult).contains(secondSessionId);

            assertThat(hibernateSession.getStatistics()
                    .getEntityCount()).isZero();
        });
    }

    @Test
    void findSessionIdByTokenHash_withoutTransaction_returnsExpectedResult() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken existingToken =
                persistRefreshToken(sessionId);

        String unknownHash = generateTokenHash();

        assertThat(unknownHash)
                .isNotEqualTo(existingToken.getTokenHash());

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive()).isFalse();

        Optional<UUID> result =
                refreshTokenRepository
                        .findSessionIdByTokenHash(unknownHash);

        assertThat(result).isEmpty();

        Optional<UUID> existingResult =
                refreshTokenRepository
                        .findSessionIdByTokenHash(
                                existingToken.getTokenHash()
                        );

        assertThat(existingResult)
                .contains(sessionId);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive()).isFalse();
    }

    @Test
    void findSessionIdByTokenHash_consumedAndExpiredToken_returnsSessionId() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token = newRefreshToken(sessionId);

        Instant consumedAt = CREATED_AT.plusSeconds(60);
        Instant now = TOKEN_EXPIRES_AT.plusSeconds(1);

        token.consume(consumedAt);

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.isExpired(now)).isTrue();

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        Optional<UUID> result = inTransaction(() -> {
            return refreshTokenRepository.findSessionIdByTokenHash(
                    token.getTokenHash()
            );
        });

        assertThat(result).contains(sessionId);
    }

    @Test
    void findSessionIdByTokenHash_nullHash_throwsNullPointerException() {
        assertThatThrownBy(() -> inTransaction(() -> {
            refreshTokenRepository.findSessionIdByTokenHash(null);
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("tokenHash is required");
    }

    @Test
    void findByTokenHash_knownHash_returnsManagedToken() {
        UUID userId = createUser();

        UUID firstSessionId = persistSession(userId);
        UUID secondSessionId = persistSession(userId);

        RefreshToken firstToken =
                persistRefreshToken(firstSessionId);

        RefreshToken secondToken =
                persistRefreshToken(secondSessionId);

        inTransaction(() -> {
            Session hibernateSession =
                    entityManager.unwrap(Session.class);

            assertThat(hibernateSession.getStatistics()
                    .getEntityCount()).isZero();

            Optional<RefreshToken> result =
                    refreshTokenRepository.findByTokenHash(
                            firstToken.getTokenHash()
                    );

            assertThat(result).isPresent();

            RefreshToken token = result.orElseThrow();

            assertThat(token.getId())
                    .isEqualTo(firstToken.getId())
                    .isNotEqualTo(secondToken.getId());

            assertThat(token.getSessionId())
                    .isEqualTo(firstSessionId);

            assertThat(token.getTokenHash())
                    .isEqualTo(firstToken.getTokenHash());

            assertThat(token.getCreatedAt())
                    .isEqualTo(CREATED_AT);

            assertThat(token.getExpiresAt())
                    .isEqualTo(TOKEN_EXPIRES_AT);

            assertThat(token.getConsumedAt()).isNull();

            assertThat(entityManager.contains(token))
                    .isTrue();

            assertThat(entityManager.getLockMode(token))
                    .isEqualTo(LockModeType.NONE);

            assertThat(hibernateSession.getStatistics()
                    .getEntityCount()).isEqualTo(1);
        });
    }
    @Test
    void findByTokenHash_unknownHash_returnsEmpty() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token =
                persistRefreshToken(sessionId);

        String unknownHash = generateTokenHash();

        assertThat(unknownHash)
                .isNotEqualTo(token.getTokenHash());

        Optional<RefreshToken> result = inTransaction(() -> {
            return refreshTokenRepository.findByTokenHash(
                    unknownHash
            );
        });

        assertThat(result).isEmpty();
    }
    @Test
    void findByTokenHash_consumedAndExpiredToken_returnsToken() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken token = newRefreshToken(sessionId);

        Instant consumedAt = CREATED_AT.plusSeconds(60);
        Instant now = TOKEN_EXPIRES_AT.plusSeconds(1);

        token.consume(consumedAt);

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        inTransaction(() -> {
            Optional<RefreshToken> result =
                    refreshTokenRepository.findByTokenHash(
                            token.getTokenHash()
                    );

            assertThat(result).isPresent();

            RefreshToken persistedToken =
                    result.orElseThrow();

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

            assertThat(persistedToken.isConsumed())
                    .isTrue();

            assertThat(persistedToken.isExpired(now))
                    .isTrue();

            assertThat(persistedToken.getConsumedAt())
                    .isEqualTo(consumedAt);

            assertThat(entityManager.contains(persistedToken))
                    .isTrue();

            assertThat(entityManager.getLockMode(persistedToken))
                    .isEqualTo(LockModeType.NONE);
        });
    }
    @Test
    void findByTokenHash_nullHash_throwsNullPointerException() {
        assertThatThrownBy(() -> inTransaction(() -> {
            refreshTokenRepository.findByTokenHash(null);
        }))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("tokenHash is required");
    }
}