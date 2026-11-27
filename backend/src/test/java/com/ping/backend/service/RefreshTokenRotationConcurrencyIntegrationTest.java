
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import com.ping.backend.support.MutableClock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.testcontainers.containers.PostgreSQLContainer;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import org.springframework.transaction.support.TransactionTemplate;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.exception.InvalidRefreshTokenException;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doAnswer;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(properties = {
        "spring.flyway.enabled=true",
        "spring.jpa.hibernate.ddl-auto=validate",
        "spring.jpa.open-in-view=false",
        "resend.api-key=test-api-key",
        "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
        "auth.refresh-token-ttl=30d",
        "auth.session-ttl=90d",
        "spring.datasource.hikari.maximum-pool-size=6",
        "spring.datasource.hikari.connection-timeout=5000",
        "spring.datasource.hikari.connection-init-sql=SET statement_timeout = '15s'"
})
@Import(
        RefreshTokenRotationConcurrencyIntegrationTest
                .ClockConfiguration.class
)
@Execution(ExecutionMode.SAME_THREAD)
class RefreshTokenRotationConcurrencyIntegrationTest {

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

    private static final long TIMEOUT_SECONDS = 20L;

    private static final long LOCK_OBSERVATION_TIMEOUT_SECONDS = 10L;

    private static final long LOCK_POLL_INTERVAL_MILLIS = 50L;

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

    @MockitoSpyBean
    private RefreshTokenGenerator refreshTokenGenerator;

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

    private ExecutorService executorService;

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


    private void cleanupTestData() {
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


    private void awaitLatch(
            CountDownLatch latch,
            String description
    ) {
        try {
            assertThat(latch.await(
                    TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
            ))
                    .as(description)
                    .isTrue();
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            throw new IllegalStateException(
                    "Interrupted while waiting: " + description,
                    exception
            );
        }
    }


    private <T> Future<T> submitTask(Callable<T> task) {
        return executorService.submit(task);
    }



    private <T> T awaitResult(
            Future<T> future,
            String description
    ) {
        try {
            return future.get(
                    TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
            );
        } catch (TimeoutException exception) {
            future.cancel(true);

            throw new AssertionError(
                    "Worker timed out: " + description,
                    exception
            );
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();

            future.cancel(true);

            throw new IllegalStateException(
                    "Interrupted while waiting: " + description,
                    exception
            );
        } catch (ExecutionException exception) {
            Throwable cause = exception.getCause();

            if (cause instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }

            if (cause instanceof Error error) {
                throw error;
            }

            throw new IllegalStateException(
                    "Worker execution failed: " + description,
                    cause
            );
        }
    }


    private int currentBackendPid() {
        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        )
                .as("Backend PID must be captured inside an active transaction")
                .isTrue();

        return jdbcClient.sql("SELECT pg_backend_pid()")
                .query(Integer.class)
                .single();
    }


    private List<Integer> findBlockedBackendPids(
            int blockerPid
    ) {
        return jdbcClient.sql("""
            SELECT activity.pid
            FROM pg_stat_activity activity
            WHERE activity.datname = current_database()
              AND :blockerPid = ANY(
                  pg_blocking_pids(activity.pid)
              )
            """)
                .param("blockerPid", blockerPid)
                .query(Integer.class)
                .list();
    }


    private List<Integer> awaitBlockedBackends(
            int blockerPid,
            int expectedBlockedCount
    ) {
        long deadline = System.nanoTime()
                + TimeUnit.SECONDS.toNanos(
                LOCK_OBSERVATION_TIMEOUT_SECONDS
        );

        List<Integer> blockedPids;

        do {
            blockedPids = findBlockedBackendPids(blockerPid);

            if (blockedPids.size() >= expectedBlockedCount) {
                return blockedPids;
            }

            try {
                TimeUnit.MILLISECONDS.sleep(
                        LOCK_POLL_INTERVAL_MILLIS
                );
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();

                throw new IllegalStateException(
                        "Interrupted while observing database locks",
                        exception
                );
            }
        } while (System.nanoTime() - deadline < 0);

        throw new AssertionError(
                "Expected at least " + expectedBlockedCount
                        + " blocked backend(s) for PID "
                        + blockerPid
                        + ", but observed "
                        + blockedPids
        );
    }



    @AfterEach
    void tearDown() throws InterruptedException {
        if (executorService != null) {
            executorService.shutdownNow();

            assertThat(executorService.awaitTermination(
                    TIMEOUT_SECONDS,
                    TimeUnit.SECONDS
            ))
                    .as("All worker threads must terminate before database cleanup")
                    .isTrue();
        }

        cleanupTestData();
    }


    @BeforeEach
    void setUp() {
        mutableClock.setInstant(INITIAL_TIME);

        executorService =
                Executors.newFixedThreadPool(2);
    }

    @Test
    void contextLoads_withConcurrencyInfrastructure()
            throws Exception {

        assertThat(postgres.isRunning())
                .isTrue();

        assertThat(
                jdbcClient.sql("SELECT 1")
                        .query(Integer.class)
                        .single()
        ).isEqualTo(1);

        assertThat(AopUtils.isAopProxy(rotationService))
                .isTrue();

        assertThat(AopUtils.isAopProxy(transactionService))
                .isTrue();

        assertThat(issuanceService)
                .isNotNull();

        assertThat(authSessionRepository)
                .isNotNull();

        assertThat(refreshTokenGenerator)
                .isNotNull();

        assertThat(transactionManager)
                .isNotNull();

        assertThat(clock)
                .isSameAs(mutableClock);

        assertThat(authProperties.refreshTokenTtl())
                .isEqualTo(REFRESH_TOKEN_TTL);

        assertThat(authProperties.sessionTtl())
                .isEqualTo(SESSION_TTL);

        assertThat(mutableClock.instant())
                .isEqualTo(INITIAL_TIME);

        Thread testThread =
                Thread.currentThread();

        Thread workerThread =
                executorService.submit(
                        Thread::currentThread
                ).get(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                );

        assertThat(workerThread)
                .isNotSameAs(testThread);

        assertThat(
                executorService.submit(
                        () -> TransactionSynchronizationManager
                                .isActualTransactionActive()
                ).get(
                        TIMEOUT_SECONDS,
                        TimeUnit.SECONDS
                )
        ).isFalse();

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();


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

        assertThat(sessionRow.get("user_id"))
                .isEqualTo(userId);

        assertThat(readTimestamp(
                sessionRow,
                "created_at"
        )).isEqualTo(INITIAL_TIME);

        assertThat(readTimestamp(
                sessionRow,
                "revoked_at"
        )).isNull();

        assertThat(tokenRow.get("session_id"))
                .isEqualTo(sessionId);

        assertThat(readTimestamp(
                tokenRow,
                "consumed_at"
        )).isNull();

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(1L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);


        CountDownLatch workerReady =
                new CountDownLatch(1);

        CountDownLatch releaseWorker =
                new CountDownLatch(1);

        Future<Instant> workerResult = submitTask(() -> {
            workerReady.countDown();

            awaitLatch(
                    releaseWorker,
                    "Worker must receive release signal"
            );

            return mutableClock.instant();
        });

        try {
            awaitLatch(
                    workerReady,
                    "Worker must reach synchronization point"
            );

            assertThat(workerResult.isDone())
                    .isFalse();

            mutableClock.advance(Duration.ofDays(5));
        } finally {
            releaseWorker.countDown();
        }

        assertThat(awaitResult(
                workerResult,
                "Worker clock verification"
        )).isEqualTo(
                INITIAL_TIME.plus(Duration.ofDays(5))
        );

        assertThat(workerResult.isDone())
                .isTrue();


        TransactionTemplate transactionTemplate =
                new TransactionTemplate(transactionManager);

        Integer backendPid = transactionTemplate.execute(status -> {
            int firstPid = currentBackendPid();

            int secondPid = currentBackendPid();

            assertThat(firstPid)
                    .isPositive();

            assertThat(secondPid)
                    .isEqualTo(firstPid);

            return firstPid;
        });

        assertThat(backendPid)
                .isNotNull()
                .isPositive();

        assertThat(findBlockedBackendPids(backendPid))
                .isEmpty();

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();

    }

    @Test
    void pessimisticWriteLock_blocksConcurrentTransactionUntilRelease() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String tokenHash = refreshTokenGenerator.hash(
                issuanceResult.rawRefreshToken()
        );

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(tokenHash);

        CountDownLatch lockAcquired =
                new CountDownLatch(1);

        CountDownLatch releaseLock =
                new CountDownLatch(1);

        CountDownLatch waiterStarted =
                new CountDownLatch(1);

        AtomicInteger blockerPid =
                new AtomicInteger();

        AtomicInteger waiterPid =
                new AtomicInteger();

        Future<Integer> lockOwner = submitTask(() -> {
            TransactionTemplate transactionTemplate =
                    new TransactionTemplate(transactionManager);

            return transactionTemplate.execute(status -> {
                int pid = currentBackendPid();

                blockerPid.set(pid);

                assertThat(
                        authSessionRepository
                                .findByIdForUpdate(sessionId)
                ).isPresent();

                lockAcquired.countDown();

                awaitLatch(
                        releaseLock,
                        "Lock owner must receive release signal"
                );

                return pid;
            });
        });

        Future<Integer> lockWaiter;

        try {
            awaitLatch(
                    lockAcquired,
                    "First transaction must acquire session lock"
            );

            assertThat(blockerPid.get())
                    .isPositive();

            lockWaiter = submitTask(() -> {
                TransactionTemplate transactionTemplate =
                        new TransactionTemplate(transactionManager);

                return transactionTemplate.execute(status -> {
                    int pid = currentBackendPid();

                    waiterPid.set(pid);

                    waiterStarted.countDown();

                    assertThat(
                            authSessionRepository
                                    .findByIdForUpdate(sessionId)
                    ).isPresent();

                    return pid;
                });
            });

            awaitLatch(
                    waiterStarted,
                    "Second transaction must start"
            );

            assertThat(waiterPid.get())
                    .isPositive()
                    .isNotEqualTo(blockerPid.get());

            List<Integer> blockedPids =
                    awaitBlockedBackends(
                            blockerPid.get(),
                            1
                    );

            assertThat(blockedPids)
                    .contains(waiterPid.get());

            assertThat(lockOwner.isDone())
                    .isFalse();

            assertThat(lockWaiter.isDone())
                    .isFalse();

        } finally {
            releaseLock.countDown();
        }

        assertThat(awaitResult(
                lockOwner,
                "Lock owner transaction completion"
        )).isEqualTo(blockerPid.get());

        assertThat(awaitResult(
                lockWaiter,
                "Lock waiter transaction completion"
        )).isEqualTo(waiterPid.get());

        assertThat(findBlockedBackendPids(
                blockerPid.get()
        )).doesNotContain(waiterPid.get());

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

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();
    }


    @Test
    void rotate_whenSameTokenIsUsedConcurrently_allowsOneRotationAndRevokesSession() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        mutableClock.advance(Duration.ofDays(10));

        Instant rotationTime = mutableClock.instant();

        CountDownLatch firstRequestHoldingLock =
                new CountDownLatch(1);

        CountDownLatch releaseFirstRequest =
                new CountDownLatch(1);

        AtomicInteger blockerPid =
                new AtomicInteger();

        AtomicInteger generationCalls =
                new AtomicInteger();

        doAnswer(invocation -> {
            int callNumber =
                    generationCalls.incrementAndGet();

            if (callNumber == 1) {
                blockerPid.set(currentBackendPid());

                firstRequestHoldingLock.countDown();

                awaitLatch(
                        releaseFirstRequest,
                        "First rotation must receive release signal"
                );
            }

            return invocation.callRealMethod();
        }).when(refreshTokenGenerator).generate();

        Future<RefreshTokenRotationResult> firstRequest =
                submitTask(() ->
                        rotationService.rotate(originalRawToken)
                );

        Future<RefreshTokenRotationResult> secondRequest;

        try {
            awaitLatch(
                    firstRequestHoldingLock,
                    "First rotation must reach token generation"
            );

            assertThat(blockerPid.get())
                    .isPositive();

            secondRequest = submitTask(() ->
                    rotationService.rotate(originalRawToken)
            );

            List<Integer> blockedPids =
                    awaitBlockedBackends(
                            blockerPid.get(),
                            1
                    );

            assertThat(blockedPids)
                    .hasSize(1);

            assertThat(firstRequest.isDone())
                    .isFalse();

            assertThat(secondRequest.isDone())
                    .isFalse();

            assertThat(generationCalls.get())
                    .isEqualTo(1);

        } finally {
            releaseFirstRequest.countDown();
        }

        RefreshTokenRotationResult rotationResult =
                awaitResult(
                        firstRequest,
                        "First concurrent rotation"
                );

        assertThatThrownBy(() ->
                awaitResult(
                        secondRequest,
                        "Second concurrent rotation"
                )
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(rotationResult.userId())
                .isEqualTo(userId);

        assertThat(rotationResult.sessionId())
                .isEqualTo(sessionId);

        assertThat(rotationResult.sessionExpiresAt())
                .isEqualTo(
                        issuanceResult.sessionExpiresAt()
                );

        assertThat(rotationResult.refreshTokenExpiresAt())
                .isEqualTo(
                        rotationTime.plus(REFRESH_TOKEN_TTL)
                );

        String replacementRawToken =
                rotationResult.rawRefreshToken();

        assertThat(replacementRawToken)
                .isNotBlank()
                .isNotEqualTo(originalRawToken);

        String replacementTokenHash =
                refreshTokenGenerator.hash(
                        replacementRawToken
                );

        assertThat(replacementTokenHash)
                .isNotEqualTo(originalTokenHash);

        Map<String, Object> sessionRow =
                findSession(sessionId);

        Map<String, Object> originalTokenRow =
                findTokenByHash(originalTokenHash);

        Map<String, Object> replacementTokenRow =
                findTokenByHash(replacementTokenHash);

        assertThat(readTimestamp(
                sessionRow,
                "revoked_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                originalTokenRow,
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

        assertThat(generationCalls.get())
                .isEqualTo(1);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(2L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();
    }


    @Test
    void rotate_whenTokenExpiresWhileWaitingForLock_rejectsWithoutChangingDatabase() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String rawToken =
                issuanceResult.rawRefreshToken();

        String tokenHash =
                refreshTokenGenerator.hash(rawToken);

        Instant tokenExpiration =
                issuanceResult.refreshTokenExpiresAt();

        mutableClock.setInstant(
                tokenExpiration.minusSeconds(1)
        );

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> originalToken =
                findTokenByHash(tokenHash);

        assertThat(readTimestamp(
                originalToken,
                "expires_at"
        )).isAfter(mutableClock.instant());

        assertThat(readTimestamp(
                originalToken,
                "consumed_at"
        )).isNull();

        assertThat(readTimestamp(
                originalSession,
                "revoked_at"
        )).isNull();

        CountDownLatch lockAcquired =
                new CountDownLatch(1);

        CountDownLatch releaseLock =
                new CountDownLatch(1);

        AtomicInteger blockerPid =
                new AtomicInteger();

        AtomicInteger generationCalls =
                new AtomicInteger();

        doAnswer(invocation -> {
            generationCalls.incrementAndGet();

            return invocation.callRealMethod();
        }).when(refreshTokenGenerator).generate();

        Future<Integer> lockOwner = submitTask(() -> {
            TransactionTemplate transactionTemplate =
                    new TransactionTemplate(transactionManager);

            return transactionTemplate.execute(status -> {
                int pid = currentBackendPid();

                blockerPid.set(pid);

                assertThat(
                        authSessionRepository
                                .findByIdForUpdate(sessionId)
                ).isPresent();

                lockAcquired.countDown();

                awaitLatch(
                        releaseLock,
                        "Lock owner must receive release signal"
                );

                return pid;
            });
        });

        Future<RefreshTokenRotationResult> rotationRequest;

        try {
            awaitLatch(
                    lockAcquired,
                    "Session lock must be acquired"
            );

            assertThat(blockerPid.get())
                    .isPositive();

            rotationRequest = submitTask(() ->
                    rotationService.rotate(rawToken)
            );

            List<Integer> blockedPids =
                    awaitBlockedBackends(
                            blockerPid.get(),
                            1
                    );

            assertThat(blockedPids)
                    .hasSize(1);

            assertThat(rotationRequest.isDone())
                    .isFalse();

            assertThat(lockOwner.isDone())
                    .isFalse();

            assertThat(generationCalls.get())
                    .isZero();

            assertThat(mutableClock.instant())
                    .isBefore(tokenExpiration);

            mutableClock.advance(
                    Duration.ofSeconds(1)
            );

            assertThat(mutableClock.instant())
                    .isEqualTo(tokenExpiration);

            assertThat(
                    issuanceResult.sessionExpiresAt()
            ).isAfter(mutableClock.instant());

        } finally {
            releaseLock.countDown();
        }

        assertThat(awaitResult(
                lockOwner,
                "Session lock owner completion"
        )).isEqualTo(blockerPid.get());

        assertThatThrownBy(() ->
                awaitResult(
                        rotationRequest,
                        "Rotation after token expiration"
                )
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(generationCalls.get())
                .isZero();

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

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();
    }


    @Test
    void rotate_whenSessionExpiresWhileWaitingForLock_rejectsReuseWithoutRevocation() {
        UUID userId = createUser();

        RefreshTokenIssuanceResult issuanceResult =
                issueRefreshToken(userId);

        UUID sessionId = issuanceResult.sessionId();

        String originalRawToken =
                issuanceResult.rawRefreshToken();

        String originalTokenHash =
                refreshTokenGenerator.hash(originalRawToken);

        String currentRawToken = originalRawToken;

        Instant sessionExpiration =
                issuanceResult.sessionExpiresAt();

        for (int rotationNumber = 1;
             rotationNumber <= 3;
             rotationNumber++) {

            mutableClock.advance(Duration.ofDays(25));

            RefreshTokenRotationResult rotationResult =
                    rotationService.rotate(currentRawToken);

            currentRawToken =
                    rotationResult.rawRefreshToken();

            assertThat(rotationResult.sessionId())
                    .isEqualTo(sessionId);

            assertThat(rotationResult.sessionExpiresAt())
                    .isEqualTo(sessionExpiration);
        }

        String latestRawToken = currentRawToken;

        String latestTokenHash =
                refreshTokenGenerator.hash(latestRawToken);

        mutableClock.setInstant(
                sessionExpiration.minusSeconds(1)
        );

        Map<String, Object> originalSession =
                findSession(sessionId);

        Map<String, Object> consumedToken =
                findTokenByHash(originalTokenHash);

        Map<String, Object> latestToken =
                findTokenByHash(latestTokenHash);

        assertThat(readTimestamp(
                originalSession,
                "expires_at"
        )).isAfter(mutableClock.instant());

        assertThat(readTimestamp(
                originalSession,
                "revoked_at"
        )).isNull();

        assertThat(readTimestamp(
                consumedToken,
                "consumed_at"
        )).isNotNull();

        assertThat(readTimestamp(
                consumedToken,
                "expires_at"
        )).isBefore(mutableClock.instant());

        assertThat(readTimestamp(
                latestToken,
                "expires_at"
        )).isEqualTo(sessionExpiration);

        assertThat(readTimestamp(
                latestToken,
                "consumed_at"
        )).isNull();

        assertThat(countTokens(sessionId))
                .isEqualTo(4L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        CountDownLatch lockAcquired =
                new CountDownLatch(1);

        CountDownLatch releaseLock =
                new CountDownLatch(1);

        AtomicInteger blockerPid =
                new AtomicInteger();

        AtomicInteger generationCalls =
                new AtomicInteger();

        doAnswer(invocation -> {
            generationCalls.incrementAndGet();

            return invocation.callRealMethod();
        }).when(refreshTokenGenerator).generate();

        Future<Integer> lockOwner = submitTask(() -> {
            TransactionTemplate transactionTemplate =
                    new TransactionTemplate(transactionManager);

            return transactionTemplate.execute(status -> {
                int pid = currentBackendPid();

                blockerPid.set(pid);

                assertThat(
                        authSessionRepository
                                .findByIdForUpdate(sessionId)
                ).isPresent();

                lockAcquired.countDown();

                awaitLatch(
                        releaseLock,
                        "Lock owner must receive release signal"
                );

                return pid;
            });
        });

        Future<RefreshTokenRotationResult> rotationRequest;

        try {
            awaitLatch(
                    lockAcquired,
                    "Session lock must be acquired"
            );

            assertThat(blockerPid.get())
                    .isPositive();

            rotationRequest = submitTask(() ->
                    rotationService.rotate(originalRawToken)
            );

            List<Integer> blockedPids =
                    awaitBlockedBackends(
                            blockerPid.get(),
                            1
                    );

            assertThat(blockedPids)
                    .hasSize(1);

            assertThat(rotationRequest.isDone())
                    .isFalse();

            assertThat(lockOwner.isDone())
                    .isFalse();

            assertThat(mutableClock.instant())
                    .isBefore(sessionExpiration);

            mutableClock.advance(
                    Duration.ofSeconds(1)
            );

            assertThat(mutableClock.instant())
                    .isEqualTo(sessionExpiration);

        } finally {
            releaseLock.countDown();
        }

        assertThat(awaitResult(
                lockOwner,
                "Session lock owner completion"
        )).isEqualTo(blockerPid.get());

        assertThatThrownBy(() ->
                awaitResult(
                        rotationRequest,
                        "Reuse after session expiration"
                )
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(consumedToken);

        assertThat(findTokenByHash(latestTokenHash))
                .isEqualTo(latestToken);

        assertThatThrownBy(() ->
                rotationService.rotate(latestRawToken)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        assertThat(generationCalls.get())
                .isZero();

        assertThat(findSession(sessionId))
                .isEqualTo(originalSession);

        assertThat(findTokenByHash(originalTokenHash))
                .isEqualTo(consumedToken);

        assertThat(findTokenByHash(latestTokenHash))
                .isEqualTo(latestToken);

        assertThat(countSessions(userId))
                .isEqualTo(1L);

        assertThat(countTokens(sessionId))
                .isEqualTo(4L);

        assertThat(countUnconsumedTokens(sessionId))
                .isEqualTo(1L);

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();
    }


    @Test
    void rotate_whenIndependentSessionsAreUsedConcurrently_allowsBothRotations() {
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

        String firstRawToken =
                firstIssuance.rawRefreshToken();

        String secondRawToken =
                secondIssuance.rawRefreshToken();

        String firstOriginalTokenHash =
                refreshTokenGenerator.hash(firstRawToken);

        String secondOriginalTokenHash =
                refreshTokenGenerator.hash(secondRawToken);

        Map<String, Object> firstOriginalSession =
                findSession(firstSessionId);

        Map<String, Object> secondOriginalSession =
                findSession(secondSessionId);

        Map<String, Object> firstOriginalToken =
                findTokenByHash(firstOriginalTokenHash);

        mutableClock.advance(Duration.ofDays(10));

        Instant rotationTime = mutableClock.instant();

        CountDownLatch firstRequestHoldingLock =
                new CountDownLatch(1);

        CountDownLatch releaseFirstRequest =
                new CountDownLatch(1);

        AtomicInteger firstBackendPid =
                new AtomicInteger();

        AtomicInteger secondBackendPid =
                new AtomicInteger();

        AtomicInteger generationCalls =
                new AtomicInteger();

        doAnswer(invocation -> {
            int callNumber =
                    generationCalls.incrementAndGet();

            if (callNumber == 1) {
                firstBackendPid.set(currentBackendPid());

                firstRequestHoldingLock.countDown();

                awaitLatch(
                        releaseFirstRequest,
                        "First rotation must receive release signal"
                );
            } else if (callNumber == 2) {
                secondBackendPid.set(currentBackendPid());
            }

            return invocation.callRealMethod();
        }).when(refreshTokenGenerator).generate();

        Future<RefreshTokenRotationResult> firstRequest =
                submitTask(() ->
                        rotationService.rotate(firstRawToken)
                );

        RefreshTokenRotationResult secondResult;

        try {
            awaitLatch(
                    firstRequestHoldingLock,
                    "First rotation must hold its session lock"
            );

            assertThat(firstBackendPid.get())
                    .isPositive();

            Future<RefreshTokenRotationResult> secondRequest =
                    submitTask(() ->
                            rotationService.rotate(secondRawToken)
                    );

            secondResult = awaitResult(
                    secondRequest,
                    "Independent session must rotate before first lock is released"
            );

            assertThat(secondBackendPid.get())
                    .isPositive()
                    .isNotEqualTo(firstBackendPid.get());

            assertThat(firstRequest.isDone())
                    .isFalse();

            assertThat(secondRequest.isDone())
                    .isTrue();

            assertThat(generationCalls.get())
                    .isEqualTo(2);

            assertThat(secondResult.userId())
                    .isEqualTo(userId);

            assertThat(secondResult.sessionId())
                    .isEqualTo(secondSessionId);

            assertThat(findSession(firstSessionId))
                    .isEqualTo(firstOriginalSession);

            assertThat(findTokenByHash(firstOriginalTokenHash))
                    .isEqualTo(firstOriginalToken);

            assertThat(countTokens(firstSessionId))
                    .isEqualTo(1L);

            assertThat(countTokens(secondSessionId))
                    .isEqualTo(2L);

            assertThat(readTimestamp(
                    findTokenByHash(secondOriginalTokenHash),
                    "consumed_at"
            )).isEqualTo(rotationTime);

            assertThat(firstRequest.isDone())
                    .isFalse();

        } finally {
            releaseFirstRequest.countDown();
        }

        RefreshTokenRotationResult firstResult =
                awaitResult(
                        firstRequest,
                        "First independent session rotation"
                );

        assertThat(firstResult.userId())
                .isEqualTo(userId);

        assertThat(firstResult.sessionId())
                .isEqualTo(firstSessionId);

        assertThat(firstResult.sessionExpiresAt())
                .isEqualTo(firstIssuance.sessionExpiresAt());

        assertThat(secondResult.sessionExpiresAt())
                .isEqualTo(secondIssuance.sessionExpiresAt());

        assertThat(firstResult.refreshTokenExpiresAt())
                .isEqualTo(rotationTime.plus(REFRESH_TOKEN_TTL));

        assertThat(secondResult.refreshTokenExpiresAt())
                .isEqualTo(rotationTime.plus(REFRESH_TOKEN_TTL));

        assertThat(firstResult.rawRefreshToken())
                .isNotEqualTo(firstRawToken)
                .isNotEqualTo(secondRawToken)
                .isNotEqualTo(secondResult.rawRefreshToken());

        assertThat(secondResult.rawRefreshToken())
                .isNotEqualTo(firstRawToken)
                .isNotEqualTo(secondRawToken);

        String firstReplacementTokenHash =
                refreshTokenGenerator.hash(
                        firstResult.rawRefreshToken()
                );

        String secondReplacementTokenHash =
                refreshTokenGenerator.hash(
                        secondResult.rawRefreshToken()
                );

        Map<String, Object> firstReplacementToken =
                findTokenByHash(firstReplacementTokenHash);

        Map<String, Object> secondReplacementToken =
                findTokenByHash(secondReplacementTokenHash);

        assertThat(firstReplacementToken.get("session_id"))
                .isEqualTo(firstSessionId);

        assertThat(secondReplacementToken.get("session_id"))
                .isEqualTo(secondSessionId);

        assertThat(readTimestamp(
                findTokenByHash(firstOriginalTokenHash),
                "consumed_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                findTokenByHash(secondOriginalTokenHash),
                "consumed_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                firstReplacementToken,
                "created_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                secondReplacementToken,
                "created_at"
        )).isEqualTo(rotationTime);

        assertThat(readTimestamp(
                firstReplacementToken,
                "expires_at"
        )).isEqualTo(firstResult.refreshTokenExpiresAt());

        assertThat(readTimestamp(
                secondReplacementToken,
                "expires_at"
        )).isEqualTo(secondResult.refreshTokenExpiresAt());

        assertThat(readTimestamp(
                firstReplacementToken,
                "consumed_at"
        )).isNull();

        assertThat(readTimestamp(
                secondReplacementToken,
                "consumed_at"
        )).isNull();

        assertThat(findSession(firstSessionId))
                .isEqualTo(firstOriginalSession);

        assertThat(findSession(secondSessionId))
                .isEqualTo(secondOriginalSession);

        assertThat(generationCalls.get())
                .isEqualTo(2);

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

        assertThat(
                TransactionSynchronizationManager
                        .isActualTransactionActive()
        ).isFalse();
    }



}
