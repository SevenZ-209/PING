
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
import org.springframework.jdbc.core.simple.JdbcClient;
import java.util.UUID;
import com.ping.backend.service.EmailVerificationService;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.reset;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import com.ping.backend.service.EmailSender;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.ArgumentMatchers.eq;


@SpringBootTest
class AuthServiceIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @MockitoBean
    private EmailSender emailSender;

    @Autowired
    private AuthService authService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JdbcClient jdbcClient;

    @MockitoSpyBean
    private EmailVerificationService emailVerificationService;

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

        verify(emailSender, times(1))
                .sendVerificationEmail(
                        eq(email),
                        any(String.class)
                );

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

        Integer tokenCount = jdbcClient.sql("""
        SELECT COUNT(*)
        FROM email_verification_tokens
        WHERE user_id = :userId
        """)
                .param("userId", savedUser.getId())
                .query(Integer.class)
                .single();

        assertThat(tokenCount).isEqualTo(1);
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

    @Test
    void register_whenTokenIssuanceFails_rollsBackUser() {
        String email = "rollback-" + UUID.randomUUID()
                + "@example.com";

        RegisterRequest request = new RegisterRequest(
                email,
                "password123",
                "Rollback User"
        );

        doThrow(new IllegalStateException("Simulated token failure"))
                .when(emailVerificationService)
                .issueToken(any(UUID.class));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Simulated token failure");

        assertThat(userRepository.findByEmail(email))
                .isEmpty();

        verify(emailSender, never())
                .sendVerificationEmail(
                        eq(email),
                        any(String.class)
                );
    }

    @Test
    void register_whenFailureOccursAfterTokenInsert_rollsBackBoth() {
        String email = "rollback-jdbc-" + UUID.randomUUID()
                + "@example.com";

        RegisterRequest request = new RegisterRequest(
                email,
                "password123",
                "Rollback JDBC User"
        );

        doAnswer(invocation -> {
            invocation.callRealMethod();

            throw new IllegalStateException(
                    "Simulated failure after token insert"
            );
        }).when(emailVerificationService).issueToken(any(UUID.class));

        try {
            assertThatThrownBy(() -> authService.register(request))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("Simulated failure after token insert");
        } finally {
            reset(emailVerificationService);
        }

        assertThat(userRepository.findByEmail(email)).isEmpty();

        Integer tokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens t
            JOIN users u ON u.id = t.user_id
            WHERE u.email = :email
            """)
                .param("email", email)
                .query(Integer.class)
                .single();

        assertThat(tokenCount).isZero();

        verify(emailSender, never())
                .sendVerificationEmail(
                        eq(email),
                        any(String.class)
                );
    }
}
