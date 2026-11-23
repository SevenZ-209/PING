
package com.ping.backend.controller;

import com.ping.backend.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import com.ping.backend.service.EmailVerificationService;
import java.util.UUID;
import com.ping.backend.security.VerificationTokenGenerator;
import org.springframework.jdbc.core.simple.JdbcClient;
import java.time.OffsetDateTime;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JdbcClient jdbcClient;

    @Autowired
    private VerificationTokenGenerator tokenGenerator;

    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailVerificationService verificationService;
    @Test
    void register_validRequest_returns201AndPersistsUser()
            throws Exception {

        String email = "api-" + UUID.randomUUID()
                + "@example.com";

        String requestBody = """
                {
                  "email": "%s",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message")
                        .value("Registration successful"));

        var savedUser = userRepository.findByEmail(email);

        assertThat(savedUser).isPresent();
        assertThat(savedUser.orElseThrow().getDisplayName())
                .isEqualTo("Test User");
    }

    @Test
    void register_invalidEmail_returns400()
            throws Exception {

        String requestBody = """
                {
                  "email": "",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_REGISTRATION"));
    }

    @Test
    void register_duplicateEmail_returns409()
            throws Exception {

        String email = "duplicate-api-" + UUID.randomUUID()
                + "@example.com";

        String requestBody = """
                {
                  "email": "%s",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code")
                        .value("EMAIL_ALREADY_EXISTS"));
    }

    @Test
    void verifyEmail_invalidToken_returns400() throws Exception {
        String requestBody = """
            {
              "token": "invalid-verification-token"
            }
            """;

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_VERIFICATION_TOKEN"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid or expired verification token"));
    }

    @Test
    void verifyEmail_validToken_returns200AndVerifiesUser() throws Exception {
        String email = "verify-api-" + UUID.randomUUID() + "@example.com";

        String requestBody = """
            {
              "email": "%s",
              "password": "password123",
              "displayName": "Test User"
            }
            """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated());

        var user = userRepository.findByEmail(email).orElseThrow();

        String rawToken = verificationService.issueToken(user.getId());

        String verifyRequest = """
            {
              "token": "%s"
            }
            """.formatted(rawToken);

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("Email verified successfully"));

        var verifiedUser = userRepository.findByEmail(email).orElseThrow();

        assertThat(verifiedUser.getEmailVerifiedAt()).isNotNull();
    }

    @Test
    void verifyEmail_consumedToken_returns400() throws Exception {
        String email = "verify-consumed-" + UUID.randomUUID() + "@example.com";

        String registerRequest = """
            {
              "email": "%s",
              "password": "password123",
              "displayName": "Test User"
            }
            """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isCreated());

        var user = userRepository.findByEmail(email).orElseThrow();
        String rawToken = verificationService.issueToken(user.getId());

        String verifyRequest = """
            {
              "token": "%s"
            }
            """.formatted(rawToken);

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyRequest))
                .andExpect(status().isOk());

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyRequest))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_VERIFICATION_TOKEN"));
    }

    @Test
    void verifyEmail_blankToken_returns400() throws Exception {
        String requestBody = """
            {
              "token": ""
            }
            """;

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest());
    }


    @Test
    void verifyEmail_expiredToken_returns400() throws Exception {
        String email = "verify-expired-" + UUID.randomUUID() + "@example.com";

        String registerRequest = """
            {
              "email": "%s",
              "password": "password123",
              "displayName": "Test User"
            }
            """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(registerRequest))
                .andExpect(status().isCreated());

        var user = userRepository.findByEmail(email).orElseThrow();
        String rawToken = verificationService.issueToken(user.getId());

        jdbcClient.sql("""
            UPDATE email_verification_tokens
            SET created_at = :createdAt,
                expires_at = :expiresAt
            WHERE token_hash = :tokenHash
            """)
                .param("createdAt", OffsetDateTime.now().minusHours(25))
                .param("expiresAt", OffsetDateTime.now().minusHours(1))
                .param("tokenHash", tokenGenerator.hash(rawToken))
                .update();

        String verifyRequest = """
            {
              "token": "%s"
            }
            """.formatted(rawToken);

        mockMvc.perform(post("/api/v1/auth/verify-email")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(verifyRequest))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_VERIFICATION_TOKEN"));

        var unchangedUser = userRepository.findByEmail(email).orElseThrow();

        assertThat(unchangedUser.getEmailVerifiedAt()).isNull();
    }

}
