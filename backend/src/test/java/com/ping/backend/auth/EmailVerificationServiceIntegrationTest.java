package com.ping.backend.auth;
import com.ping.backend.service.EmailVerificationService;
import com.ping.backend.security.VerificationTokenGenerator;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.testcontainers.containers.PostgreSQLContainer;

import java.time.OffsetDateTime;
import java.util.UUID;

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
}
