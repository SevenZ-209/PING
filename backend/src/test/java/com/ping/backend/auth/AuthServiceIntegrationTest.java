
package com.ping.backend.auth;

import com.ping.backend.service.AuthService;
import com.ping.backend.repository.UserRepository;
import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.exception.EmailAlreadyExistsException;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class AuthServiceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void register_validRequest_persistsUserInPostgres() {
        String email = "register-" + UUID.randomUUID()
                + "@example.com";
        String rawPassword = "password123";

        RegisterRequest request = new RegisterRequest(
                "  " + email.toUpperCase() + "  ",
                rawPassword,
                "  Test User  "
        );

        authService.register(request);

        var result = userRepository.findByEmail(email);

        assertThat(result).isPresent();

        var savedUser = result.orElseThrow();

        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getDisplayName())
                .isEqualTo("Test User");

        assertThat(savedUser.getPasswordHash())
                .isNotEqualTo(rawPassword);

        assertThat(passwordEncoder.matches(
                rawPassword,
                savedUser.getPasswordHash()
        )).isTrue();

        assertThat(savedUser.getEmailVerifiedAt()).isNull();
    }

    @Test
    void register_existingEmail_throwsEmailAlreadyExistsException() {
        String email = "duplicate-" + UUID.randomUUID()
                + "@example.com";

        RegisterRequest firstRequest = new RegisterRequest(
                email,
                "password123",
                "First User"
        );

        RegisterRequest secondRequest = new RegisterRequest(
                email,
                "anotherPassword123",
                "Second User"
        );

        authService.register(firstRequest);

        assertThatThrownBy(() -> authService.register(secondRequest))
                .isInstanceOf(EmailAlreadyExistsException.class);

        var result = userRepository.findByEmail(email);

        assertThat(result).isPresent();
        assertThat(result.orElseThrow().getDisplayName())
                .isEqualTo("First User");
    }
}
