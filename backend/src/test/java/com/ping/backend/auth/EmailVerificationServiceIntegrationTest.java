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


}
