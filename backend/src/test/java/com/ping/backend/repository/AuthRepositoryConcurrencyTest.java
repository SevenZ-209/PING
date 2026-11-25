package com.ping.backend.repository;

import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.TransactionRequiredException;
import org.hibernate.Session;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.dao.InvalidDataAccessApiUsageException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "spring.datasource.hikari.maximum-pool-size=5",
        "spring.datasource.hikari.connection-timeout=10000",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
})
class AuthRepositoryConcurrencyTest {

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

    private static final int WAIT_TIMEOUT_SECONDS = 10;

    private static final int HOLD_TIMEOUT_SECONDS = 30;

    private static final int TRANSACTION_TIMEOUT_SECONDS = 60;

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

    private ExecutorService executorService;

    private final List<UUID> createdUserIds = new ArrayList<>();

    @BeforeEach
    void setUp() {
        transactionTemplate =
                new TransactionTemplate(transactionManager);

        transactionTemplate.setPropagationBehavior(
                TransactionDefinition.PROPAGATION_REQUIRES_NEW
        );

        transactionTemplate.setIsolationLevel(
                TransactionDefinition.ISOLATION_READ_COMMITTED
        );

        transactionTemplate.setTimeout(
                TRANSACTION_TIMEOUT_SECONDS
        );

        executorService = Executors.newFixedThreadPool(2);
    }

    @AfterEach
    void cleanupTestData() {
        shutdownExecutor();

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

    private UUID persistSession(UUID userId) {
        AuthSession session = new AuthSession(
                UUID.randomUUID(),
                userId,
                CREATED_AT,
                SESSION_EXPIRES_AT
        );

        inTransaction(() -> {
            entityManager.persist(session);
            entityManager.flush();
        });

        return session.getId();
    }

    private RefreshToken persistRefreshToken(UUID sessionId) {
        RefreshToken token = new RefreshToken(
                UUID.randomUUID(),
                sessionId,
                generateTokenHash(),
                CREATED_AT,
                TOKEN_EXPIRES_AT
        );

        inTransaction(() -> {
            entityManager.persist(token);
            entityManager.flush();
        });

        return token;
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

    private void awaitLatch(CountDownLatch latch) {
        awaitLatch(latch, WAIT_TIMEOUT_SECONDS);
    }

    private void awaitLatch(
            CountDownLatch latch,
            int timeoutSeconds
    ) {
        try {
            if (!latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
                throw new AssertionError(
                        "Timed out waiting for latch after "
                                + timeoutSeconds + " seconds"
                );
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            throw new AssertionError(
                    "Interrupted while waiting for latch",
                    exception
            );
        }
    }

    private <T> T awaitFuture(Future<T> future) throws Exception {
        try {
            return future.get(
                    WAIT_TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
            );
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();

            if (cause instanceof Error error) {
                throw error;
            }

            if (cause instanceof Exception workerException) {
                throw workerException;
            }

            throw new AssertionError(
                    "Worker execution failed",
                    cause
            );
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw exception;
        }
    }

    private int currentBackendPid() {
        Number result = (Number) entityManager
                .createNativeQuery("SELECT pg_backend_pid()")
                .getSingleResult();

        return result.intValue();
    }

    private boolean isBlockedBy(
            int waitingBackendPid,
            int blockingBackendPid
    ) {
        return inTransaction(() -> {
            jdbcClient.sql("""
                SET LOCAL statement_timeout = '5s'
                """)
                    .update();

            return jdbcClient.sql("""
                SELECT :blockingPid = ANY(
                    pg_blocking_pids(:waitingPid)
                )
                """)
                    .param("blockingPid", blockingBackendPid)
                    .param("waitingPid", waitingBackendPid)
                    .query(Boolean.class)
                    .single();
        });
    }

    private void awaitDatabaseBlocking(
            int waitingBackendPid,
            int blockingBackendPid
    ) {
        long deadline = System.nanoTime()
                + TimeUnit.SECONDS.toNanos(WAIT_TIMEOUT_SECONDS);

        while (System.nanoTime() < deadline) {
            if (isBlockedBy(
                    waitingBackendPid,
                    blockingBackendPid
            )) {
                return;
            }

            try {
                Thread.sleep(50);
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();

                throw new AssertionError(
                        "Interrupted while inspecting database locks",
                        exception
                );
            }
        }

        throw new AssertionError(
                "Expected backend " + waitingBackendPid
                        + " to be blocked by backend "
                        + blockingBackendPid
        );
    }

    private void configureDatabaseTimeouts() {
        entityManager.createNativeQuery("""
                SET LOCAL lock_timeout = '15s'
                """).executeUpdate();

        entityManager.createNativeQuery("""
                SET LOCAL statement_timeout = '20s'
                """).executeUpdate();
    }

    private void shutdownExecutor() {
        executorService.shutdownNow();

        try {
            if (!executorService.awaitTermination(
                    TRANSACTION_TIMEOUT_SECONDS + 5,
                    TimeUnit.SECONDS
            )) {
                throw new AssertionError(
                        "Executor did not terminate"
                );
            }
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            throw new AssertionError(
                    "Interrupted while shutting down executor",
                    exception
            );
        }
    }

    @Test
    void findByIdForUpdate_withoutTransaction_throwsTransactionRequiredException() {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        assertThat(TransactionSynchronizationManager
                .isActualTransactionActive()).isFalse();

        assertThatThrownBy(() ->
                authSessionRepository.findByIdForUpdate(sessionId)
        )
                .isInstanceOf(InvalidDataAccessApiUsageException.class)
                .hasRootCauseInstanceOf(TransactionRequiredException.class);

        inTransaction(() -> {
            AuthSession session = entityManager.find(
                    AuthSession.class,
                    sessionId
            );

            assertThat(session).isNotNull();

            assertThat(session.getId())
                    .isEqualTo(sessionId);

            assertThat(session.getUserId())
                    .isEqualTo(userId);

            assertThat(session.getCreatedAt())
                    .isEqualTo(CREATED_AT);

            assertThat(session.getExpiresAt())
                    .isEqualTo(SESSION_EXPIRES_AT);

            assertThat(session.getRevokedAt()).isNull();
        });
    }

    @Test
    void findByIdForUpdate_sameSession_serializesConcurrentTransactions()
            throws Exception {
        UUID userId = createUser();
        UUID sessionId = persistSession(userId);

        RefreshToken fixtureToken =
                persistRefreshToken(sessionId);

        String tokenHash = fixtureToken.getTokenHash();
        UUID tokenId = fixtureToken.getId();

        Instant consumedAt = CREATED_AT.plusSeconds(60);

        CountDownLatch firstTransactionReady =
                new CountDownLatch(1);

        CountDownLatch secondTransactionReady =
                new CountDownLatch(1);

        CountDownLatch releaseFirstTransaction =
                new CountDownLatch(1);

        AtomicInteger firstBackendPid =
                new AtomicInteger();

        AtomicInteger secondBackendPid =
                new AtomicInteger();

        Future<Void> firstFuture = executorService.submit(() -> {
            inTransaction(() -> {
                configureDatabaseTimeouts();

                firstBackendPid.set(currentBackendPid());

                AuthSession session = authSessionRepository
                        .findByIdForUpdate(sessionId)
                        .orElseThrow();

                assertThat(entityManager.getLockMode(session))
                        .isEqualTo(LockModeType.PESSIMISTIC_WRITE);

                RefreshToken token = refreshTokenRepository
                        .findByTokenHash(tokenHash)
                        .orElseThrow();

                assertThat(token.isConsumed()).isFalse();

                token.consume(consumedAt);

                entityManager.flush();

                firstTransactionReady.countDown();

                awaitLatch(
                        releaseFirstTransaction,
                        HOLD_TIMEOUT_SECONDS
                );
            });

            return null;
        });

        try {
            awaitLatch(firstTransactionReady);

            Future<Instant> secondFuture =
                    executorService.submit(() ->
                            inTransaction(() -> {
                                configureDatabaseTimeouts();

                                secondBackendPid.set(
                                        currentBackendPid()
                                );

                                UUID resolvedSessionId =
                                        refreshTokenRepository
                                                .findSessionIdByTokenHash(
                                                        tokenHash
                                                )
                                                .orElseThrow();

                                assertThat(resolvedSessionId)
                                        .isEqualTo(sessionId);

                                Session hibernateSession =
                                        entityManager.unwrap(
                                                Session.class
                                        );

                                assertThat(hibernateSession
                                        .getStatistics()
                                        .getEntityCount())
                                        .isZero();

                                secondTransactionReady.countDown();

                                AuthSession session =
                                        authSessionRepository
                                                .findByIdForUpdate(
                                                        resolvedSessionId
                                                )
                                                .orElseThrow();

                                assertThat(entityManager
                                        .getLockMode(session))
                                        .isEqualTo(
                                                LockModeType.PESSIMISTIC_WRITE
                                        );

                                RefreshToken token =
                                        refreshTokenRepository
                                                .findByTokenHash(tokenHash)
                                                .orElseThrow();

                                assertThat(token.getId())
                                        .isEqualTo(tokenId);

                                assertThat(token.isConsumed())
                                        .isTrue();

                                assertThat(token.getConsumedAt())
                                        .isEqualTo(consumedAt);

                                return token.getConsumedAt();
                            })
                    );

            awaitLatch(secondTransactionReady);

            assertThat(firstBackendPid.get()).isPositive();
            assertThat(secondBackendPid.get()).isPositive();

            assertThat(firstBackendPid.get())
                    .isNotEqualTo(secondBackendPid.get());

            awaitDatabaseBlocking(
                    secondBackendPid.get(),
                    firstBackendPid.get()
            );

            assertThat(firstFuture.isDone()).isFalse();
            assertThat(secondFuture.isDone()).isFalse();

            releaseFirstTransaction.countDown();

            awaitFuture(firstFuture);

            Instant observedConsumedAt =
                    awaitFuture(secondFuture);

            assertThat(observedConsumedAt)
                    .isEqualTo(consumedAt);

            inTransaction(() -> {
                RefreshToken persistedToken =
                        entityManager.find(
                                RefreshToken.class,
                                tokenId
                        );

                assertThat(persistedToken).isNotNull();
                assertThat(persistedToken.isConsumed()).isTrue();

                assertThat(persistedToken.getConsumedAt())
                        .isEqualTo(consumedAt);
            });
        } finally {
            releaseFirstTransaction.countDown();
        }
    }

    @Test
    void findByIdForUpdate_differentSessions_allowsIndependentTransactions()
            throws Exception {
        UUID userId = createUser();

        UUID firstSessionId = persistSession(userId);
        UUID secondSessionId = persistSession(userId);

        Instant revokedAt = CREATED_AT.plusSeconds(60);

        CountDownLatch firstTransactionReady =
                new CountDownLatch(1);

        CountDownLatch releaseFirstTransaction =
                new CountDownLatch(1);

        AtomicInteger firstBackendPid =
                new AtomicInteger();

        AtomicInteger secondBackendPid =
                new AtomicInteger();

        Future<Void> firstFuture = executorService.submit(() -> {
            inTransaction(() -> {
                configureDatabaseTimeouts();

                firstBackendPid.set(currentBackendPid());

                AuthSession session = authSessionRepository
                        .findByIdForUpdate(firstSessionId)
                        .orElseThrow();

                assertThat(session.getId())
                        .isEqualTo(firstSessionId);

                assertThat(entityManager.getLockMode(session))
                        .isEqualTo(LockModeType.PESSIMISTIC_WRITE);

                assertThat(session.isRevoked()).isFalse();

                firstTransactionReady.countDown();

                awaitLatch(
                        releaseFirstTransaction,
                        HOLD_TIMEOUT_SECONDS
                );
            });

            return null;
        });

        try {
            awaitLatch(firstTransactionReady);

            Future<UUID> secondFuture =
                    executorService.submit(() ->
                            inTransaction(() -> {
                                configureDatabaseTimeouts();

                                secondBackendPid.set(
                                        currentBackendPid()
                                );

                                AuthSession session =
                                        authSessionRepository
                                                .findByIdForUpdate(
                                                        secondSessionId
                                                )
                                                .orElseThrow();

                                assertThat(session.getId())
                                        .isEqualTo(secondSessionId);

                                assertThat(session.getUserId())
                                        .isEqualTo(userId);

                                assertThat(entityManager
                                        .getLockMode(session))
                                        .isEqualTo(
                                                LockModeType.PESSIMISTIC_WRITE
                                        );

                                session.revoke(revokedAt);

                                entityManager.flush();

                                return session.getId();
                            })
                    );

            UUID completedSessionId =
                    awaitFuture(secondFuture);

            assertThat(completedSessionId)
                    .isEqualTo(secondSessionId);

            assertThat(firstBackendPid.get()).isPositive();
            assertThat(secondBackendPid.get()).isPositive();

            assertThat(firstBackendPid.get())
                    .isNotEqualTo(secondBackendPid.get());

            assertThat(firstFuture.isDone()).isFalse();

            releaseFirstTransaction.countDown();

            awaitFuture(firstFuture);

            inTransaction(() -> {
                AuthSession firstSession =
                        entityManager.find(
                                AuthSession.class,
                                firstSessionId
                        );

                AuthSession secondSession =
                        entityManager.find(
                                AuthSession.class,
                                secondSessionId
                        );

                assertThat(firstSession).isNotNull();
                assertThat(secondSession).isNotNull();

                assertThat(firstSession.getUserId())
                        .isEqualTo(userId);

                assertThat(secondSession.getUserId())
                        .isEqualTo(userId);

                assertThat(firstSession.isRevoked())
                        .isFalse();

                assertThat(firstSession.isActive(revokedAt))
                        .isTrue();

                assertThat(secondSession.isRevoked())
                        .isTrue();

                assertThat(secondSession.getRevokedAt())
                        .isEqualTo(revokedAt);

                assertThat(secondSession.isActive(revokedAt))
                        .isFalse();
            });
        } finally {
            releaseFirstTransaction.countDown();
        }
    }


}