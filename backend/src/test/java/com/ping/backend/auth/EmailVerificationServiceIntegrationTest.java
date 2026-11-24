package com.ping.backend.auth;
import com.ping.backend.service.EmailVerificationService;
import com.ping.backend.security.VerificationTokenGenerator;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.containers.PostgreSQLContainer;
import com.ping.backend.exception.InvalidVerificationTokenException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import java.time.OffsetDateTime;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import static org.assertj.core.api.Assertions.assertThat;
import com.ping.backend.service.EmailSender;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import com.ping.backend.dto.auth.ResendVerificationRequest;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest
class EmailVerificationServiceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @Autowired
    private EmailVerificationService verificationService;

    @Autowired
    private VerificationTokenGenerator tokenGenerator;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoBean
    private EmailSender emailSender;

    @Autowired
    private PlatformTransactionManager transactionManager;

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

        return id;
    }


    private void moveTokenOutsideCooldown(String rawToken) {
        OffsetDateTime createdAt =
                OffsetDateTime.now().minusMinutes(2);

        jdbcClient.sql("""
            UPDATE email_verification_tokens
            SET created_at = :createdAt,
                expires_at = :expiresAt
            WHERE token_hash = :tokenHash
            """)
                .param("createdAt", createdAt)
                .param("expiresAt", createdAt.plusHours(24))
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .update();
    }

    private int countTokens(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Integer.class)
                .single();
    }


    @Test
    void issueToken_storesHashInsteadOfRawToken() {
        UUID userId = createUser();

        String rawToken = verificationService.issueToken(userId);

        String storedHash = jdbcClient.sql("""
                SELECT token_hash
                FROM email_verification_tokens
                WHERE user_id = :userId
                """)
                .param("userId", userId)
                .query(String.class)
                .single();

        assertThat(rawToken).hasSize(64);
        assertThat(storedHash)
                .isEqualTo(tokenGenerator.hash(rawToken))
                .isNotEqualTo(rawToken);
    }

    @Test
    void issueToken_setsExpiryTo24Hours() {
        UUID userId = createUser();

        verificationService.issueToken(userId);

        var row = jdbcClient.sql("""
                SELECT created_at, expires_at
                FROM email_verification_tokens
                WHERE user_id = :userId
                """)
                .param("userId", userId)
                .query((rs, rowNum) -> new Object[] {
                        rs.getObject("created_at", OffsetDateTime.class),
                        rs.getObject("expires_at", OffsetDateTime.class)
                })
                .single();

        OffsetDateTime createdAt = (OffsetDateTime) row[0];
        OffsetDateTime expiresAt = (OffsetDateTime) row[1];

        assertThat(expiresAt).isEqualTo(createdAt.plusHours(24));
    }

    @Test
    void issueToken_again_invalidatesPreviousToken() {
        UUID userId = createUser();

        String first = verificationService.issueToken(userId);
        String second = verificationService.issueToken(userId);

        assertThat(second).isNotEqualTo(first);

        Integer activeCount = jdbcClient.sql("""
                SELECT COUNT(*)
                FROM email_verification_tokens
                WHERE user_id = :userId
                  AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """)
                .param("userId", userId)
                .query(Integer.class)
                .single();

        Integer invalidatedCount = jdbcClient.sql("""
                SELECT COUNT(*)
                FROM email_verification_tokens
                WHERE user_id = :userId
                  AND invalidated_at IS NOT NULL
                """)
                .param("userId", userId)
                .query(Integer.class)
                .single();

        assertThat(activeCount).isEqualTo(1);
        assertThat(invalidatedCount).isEqualTo(1);
    }


    @Test
    void verifyToken_validToken_verifiesEmailAndConsumesToken() {
        UUID userId = createUser();
        String rawToken = verificationService.issueToken(userId);

        verificationService.verifyToken(rawToken);

        OffsetDateTime emailVerifiedAt = jdbcClient.sql("""
            SELECT email_verified_at
            FROM users
            WHERE id = :userId
            """)
                .param("userId", userId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(emailVerifiedAt).isNotNull();

        OffsetDateTime consumedAt = jdbcClient.sql("""
            SELECT consumed_at
            FROM email_verification_tokens
            WHERE token_hash = :tokenHash
            """)
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .query(OffsetDateTime.class)
                .single();

        assertThat(consumedAt).isNotNull();
    }

    @Test
    void verifyToken_consumedToken_cannotBeUsedAgain() {
        UUID userId = createUser();
        String rawToken = verificationService.issueToken(userId);

        verificationService.verifyToken(rawToken);

        assertThatThrownBy(() -> verificationService.verifyToken(rawToken))
                .isInstanceOf(InvalidVerificationTokenException.class);

        Integer consumedCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens
            WHERE token_hash = :tokenHash
              AND consumed_at IS NOT NULL
            """)
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .query(Integer.class)
                .single();

        assertThat(consumedCount).isEqualTo(1);
    }

    @Test
    void verifyToken_unknownToken_throwsException() {
        String unknownToken = "a".repeat(64);

        assertThatThrownBy(() -> verificationService.verifyToken(unknownToken))
                .isInstanceOf(InvalidVerificationTokenException.class);
    }

    @Test
    void verifyToken_invalidatedToken_throwsException() {
        UUID userId = createUser();

        String firstToken = verificationService.issueToken(userId);
        verificationService.issueToken(userId);

        assertThatThrownBy(() -> verificationService.verifyToken(firstToken))
                .isInstanceOf(InvalidVerificationTokenException.class);
    }


    @Test
    void verifyToken_expiredToken_throwsException() {
        UUID userId = createUser();
        String rawToken = verificationService.issueToken(userId);


        jdbcClient.sql("""
                UPDATE email_verification_tokens
                SET created_at = :createdAt,
                    expires_at = :expiredAt
                WHERE token_hash = :tokenHash
                """)
                .param("createdAt", OffsetDateTime.now().minusHours(25))
                .param("expiredAt", OffsetDateTime.now().minusHours(1))
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .update();


        assertThatThrownBy(() -> verificationService.verifyToken(rawToken))
                .isInstanceOf(InvalidVerificationTokenException.class);

        Integer consumedCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens
            WHERE token_hash = :tokenHash
              AND consumed_at IS NOT NULL
            """)
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .query(Integer.class)
                .single();

        assertThat(consumedCount).isZero();
    }



    @Test
    void verifyToken_concurrentRequests_onlyOneSucceeds() throws Exception {
        UUID userId = createUser();
        String rawToken = verificationService.issueToken(userId);

        AtomicInteger successCount = new AtomicInteger();
        AtomicInteger rejectedCount = new AtomicInteger();

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        var executor = Executors.newFixedThreadPool(2);

        try {
            var tasks = java.util.stream.IntStream.range(0, 2)
                    .mapToObj(i -> executor.submit(() -> {
                        ready.countDown();

                        if (!start.await(10, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Start timeout");
                        }

                        try {
                            verificationService.verifyToken(rawToken);
                            successCount.incrementAndGet();
                        } catch (InvalidVerificationTokenException e) {
                            rejectedCount.incrementAndGet();
                        }

                        return null;
                    }))
                    .toList();

            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            for (var task : tasks) {
                task.get(15, TimeUnit.SECONDS);
            }
        } finally {
            start.countDown();
            executor.shutdownNow();
        }

        assertThat(successCount.get()).isEqualTo(1);
        assertThat(rejectedCount.get()).isEqualTo(1);
    }

    @Test
    void resendVerification_eligibleUser_issuesNewTokenAndSendsEmail() {
        UUID userId = createUser();
        String email = userId + "@example.com";

        String oldToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(oldToken);

        verificationService.resendVerification(
                new ResendVerificationRequest(email)
        );

        ArgumentCaptor<String> tokenCaptor =
                ArgumentCaptor.forClass(String.class);

        verify(emailSender).sendVerificationEmail(
                eq(email),
                tokenCaptor.capture()
        );

        String newToken = tokenCaptor.getValue();

        assertThat(newToken).hasSize(64);
        assertThat(newToken).isNotEqualTo(oldToken);
        assertThat(countTokens(userId)).isEqualTo(2);

        Integer invalidatedCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens
            WHERE token_hash = :tokenHash
              AND invalidated_at IS NOT NULL
            """)
                .param("tokenHash", tokenGenerator.hash(oldToken))
                .query(Integer.class)
                .single();

        assertThat(invalidatedCount).isEqualTo(1);

        assertThatThrownBy(
                () -> verificationService.verifyToken(oldToken)
        ).isInstanceOf(InvalidVerificationTokenException.class);

        verificationService.verifyToken(newToken);

        OffsetDateTime verifiedAt = jdbcClient.sql("""
            SELECT email_verified_at
            FROM users
            WHERE id = :userId
            """)
                .param("userId", userId)
                .query(OffsetDateTime.class)
                .single();

        assertThat(verifiedAt).isNotNull();
    }


    @Test
    void resendVerification_unknownEmail_doesNotSendEmail() {
        String email = UUID.randomUUID() + "@example.com";

        verificationService.resendVerification(
                new ResendVerificationRequest(email)
        );

        verifyNoInteractions(emailSender);
    }


    @Test
    void resendVerification_verifiedUser_doesNotIssueNewToken() {
        UUID userId = createUser();
        String email = userId + "@example.com";

        String rawToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(rawToken);

        verificationService.verifyToken(rawToken);

        verificationService.resendVerification(
                new ResendVerificationRequest(email)
        );

        assertThat(countTokens(userId)).isEqualTo(1);

        verifyNoInteractions(emailSender);
    }


    @Test
    void resendVerification_withinCooldown_doesNotIssueNewToken() {
        UUID userId = createUser();
        String email = userId + "@example.com";

        String rawToken = verificationService.issueToken(userId);

        verificationService.resendVerification(
                new ResendVerificationRequest(email)
        );

        assertThat(countTokens(userId)).isEqualTo(1);

        verifyNoInteractions(emailSender);

        verificationService.verifyToken(rawToken);
    }


    @Test
    void resendVerification_concurrentRequests_onlyOneIssuesToken()
            throws Exception {

        UUID userId = createUser();
        String email = userId + "@example.com";

        String oldToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(oldToken);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        var executor = Executors.newFixedThreadPool(2);

        try {
            var tasks = java.util.stream.IntStream.range(0, 2)
                    .mapToObj(i -> executor.submit(() -> {
                        ready.countDown();

                        if (!start.await(10, TimeUnit.SECONDS)) {
                            throw new IllegalStateException("Start timeout");
                        }

                        verificationService.resendVerification(
                                new ResendVerificationRequest(email)
                        );

                        return null;
                    }))
                    .toList();

            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            for (var task : tasks) {
                task.get(15, TimeUnit.SECONDS);
            }
        } finally {
            start.countDown();
            executor.shutdownNow();
        }

        assertThat(countTokens(userId)).isEqualTo(2);

        verify(emailSender, times(1))
                .sendVerificationEmail(eq(email), anyString());
    }

    @Test
    void resendVerification_concurrentWithVerify_keepsConsistentState()
            throws Exception {

        UUID userId = createUser();
        String email = userId + "@example.com";

        String oldToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(oldToken);

        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch start = new CountDownLatch(1);

        var executor = Executors.newFixedThreadPool(2);

        boolean verifySucceeded;

        try {
            var resendTask = executor.submit(() -> {
                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Start timeout");
                }

                verificationService.resendVerification(
                        new ResendVerificationRequest(email)
                );

                return null;
            });

            var verifyTask = executor.submit(() -> {
                ready.countDown();

                if (!start.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("Start timeout");
                }

                try {
                    verificationService.verifyToken(oldToken);
                    return true;
                } catch (InvalidVerificationTokenException exception) {
                    return false;
                }
            });

            assertThat(ready.await(10, TimeUnit.SECONDS)).isTrue();
            start.countDown();

            resendTask.get(15, TimeUnit.SECONDS);
            verifySucceeded = verifyTask.get(15, TimeUnit.SECONDS);

        } finally {
            start.countDown();
            executor.shutdownNow();
        }

        OffsetDateTime verifiedAt = jdbcClient.sql("""
        SELECT email_verified_at
        FROM users
        WHERE id = :userId
        """)
                .param("userId", userId)
                .query(OffsetDateTime.class)
                .optional()
                .orElse(null);


        if (verifySucceeded) {
            assertThat(verifiedAt).isNotNull();
            assertThat(countTokens(userId)).isEqualTo(1);

            verifyNoInteractions(emailSender);
        } else {
            assertThat(verifiedAt).isNull();
            assertThat(countTokens(userId)).isEqualTo(2);

            ArgumentCaptor<String> tokenCaptor =
                    ArgumentCaptor.forClass(String.class);

            verify(emailSender, times(1))
                    .sendVerificationEmail(eq(email), tokenCaptor.capture());

            assertThatThrownBy(
                    () -> verificationService.verifyToken(oldToken)
            ).isInstanceOf(InvalidVerificationTokenException.class);

            verificationService.verifyToken(tokenCaptor.getValue());
        }
    }

    @Test
    void resendVerification_sendsEmailOnlyAfterCommit() {
        UUID userId = createUser();
        String email = userId + "@example.com";

        String oldToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(oldToken);

        TransactionTemplate transactionTemplate =
                new TransactionTemplate(transactionManager);

        transactionTemplate.executeWithoutResult(status -> {
            verificationService.resendVerification(
                    new ResendVerificationRequest(email)
            );

            verifyNoInteractions(emailSender);
        });

        verify(emailSender, times(1))
                .sendVerificationEmail(eq(email), anyString());

        assertThat(countTokens(userId)).isEqualTo(2);
    }


    @Test
    void resendVerification_rollback_doesNotSendEmail() {
        UUID userId = createUser();
        String email = userId + "@example.com";

        String oldToken = verificationService.issueToken(userId);
        moveTokenOutsideCooldown(oldToken);

        TransactionTemplate transactionTemplate =
                new TransactionTemplate(transactionManager);

        transactionTemplate.executeWithoutResult(status -> {
            verificationService.resendVerification(
                    new ResendVerificationRequest(email)
            );

            verifyNoInteractions(emailSender);

            status.setRollbackOnly();
        });

        verifyNoInteractions(emailSender);

        assertThat(countTokens(userId)).isEqualTo(1);

        verificationService.verifyToken(oldToken);
    }


}
