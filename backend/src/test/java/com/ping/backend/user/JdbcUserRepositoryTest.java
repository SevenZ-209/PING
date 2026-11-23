package com.ping.backend.user;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.springframework.jdbc.core.simple.JdbcClient;
import java.util.UUID;
import java.time.Instant;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class JdbcUserRepositoryTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @Autowired
    private UserRepository userRepository;

    @Test
    void findByEmail_whenUserDoesNotExist_returnsEmpty() {
        var result = userRepository.findByEmail(
                "notfound@example.com"
        );

        assertThat(result).isEmpty();
    }


    @Autowired
    private JdbcClient jdbcClient;

    @Test
    void findByEmail_whenUserExists_returnsUser() {
        UUID userId = UUID.randomUUID();
        String email = "existing-" + userId + "@example.com";

        jdbcClient.sql("""
            INSERT INTO users (id, email, password_hash, display_name)
            VALUES (:id, :email, :passwordHash, :displayName)
            """)
                .param("id", userId)
                .param("email", email)
                .param("passwordHash", "test-hash")
                .param("displayName", "Test User")
                .update();

        var result = userRepository.findByEmail(email);

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(userId);
        assertThat(result.get().getEmail()).isEqualTo(email);
        assertThat(result.get().getDisplayName())
                .isEqualTo("Test User");
        assertThat(result.get().getEmailVerifiedAt()).isNull();
    }


    @Test
    void save_whenUserIsValid_persistsUser() {
        UUID userId = UUID.randomUUID();
        String email = "save-" + userId + "@example.com";
        Instant now = Instant.now();

        User user = new User(
                userId,
                email,
                "test-hash",
                "New User",
                now,
                now,
                null
        );

        userRepository.save(user);

        var result = userRepository.findByEmail(email);

        assertThat(result).isPresent();
        assertThat(result.get().getId()).isEqualTo(userId);
        assertThat(result.get().getEmail()).isEqualTo(email);
        assertThat(result.get().getDisplayName())
                .isEqualTo("New User");
        assertThat(result.get().getPasswordHash())
                .isEqualTo("test-hash");
        assertThat(result.get().getEmailVerifiedAt()).isNull();
    }

    @Test
    void save_whenEmailAlreadyExists_throwsException() {
        String email = "duplicate-" + UUID.randomUUID()
                + "@example.com";
        Instant now = Instant.now();

        User firstUser = new User(
                UUID.randomUUID(),
                email,
                "hash-1",
                "First User",
                now,
                now,
                null
        );

        User secondUser = new User(
                UUID.randomUUID(),
                email,
                "hash-2",
                "Second User",
                now,
                now,
                null
        );

        userRepository.save(firstUser);

        assertThatThrownBy(() -> userRepository.save(secondUser))
                .isInstanceOf(
                        org.springframework.dao.DuplicateKeyException.class
                );
    }


}
