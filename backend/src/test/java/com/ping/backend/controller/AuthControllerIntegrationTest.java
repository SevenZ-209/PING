
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
import com.ping.backend.service.EmailSender;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import static org.mockito.Mockito.doThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.verifyNoInteractions;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.http.HttpHeaders;
import tools.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;

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
    private JwtDecoder jwtDecoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private VerificationTokenGenerator tokenGenerator;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EmailVerificationService verificationService;

    @MockitoBean
    private EmailSender emailSender;


    private static final String RESEND_URL =
            "/api/v1/auth/resend-verification";

    private static final String RESEND_MESSAGE =
            "If eligible, a verification email will be sent";

    private static final String LOGIN_URL =
            "/api/v1/auth/login";

    private static final String LOGIN_PASSWORD =
            "password123";

    private String hashRefreshToken(String rawToken) throws Exception {
        byte[] hash = MessageDigest.getInstance("SHA-256")
                .digest(rawToken.getBytes(StandardCharsets.UTF_8));

        return HexFormat.of().formatHex(hash);
    }


    private UUID registerVerifiedUser(String email) throws Exception {
        UUID userId = registerUser(email);

        String rawToken = verificationService.issueToken(userId);

        verificationService.verifyToken(rawToken);

        return userId;
    }

    private String generateLoginEmail() {
        return "login-" + UUID.randomUUID() + "@example.com";
    }

    private ResultActions performLoginRequest(
            String email,
            String password
    ) throws Exception {

        String requestBody = objectMapper.writeValueAsString(
                new com.ping.backend.dto.auth.LoginRequest(
                        email,
                        password
                )
        );

        return mockMvc.perform(post(LOGIN_URL)
                .contentType(MediaType.APPLICATION_JSON)
                .content(requestBody));
    }

    private UUID registerUser(String email) throws Exception {
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

        clearInvocations(emailSender);

        return userRepository.findByEmail(email)
                .orElseThrow()
                .getId();
    }

    private void moveTokensOutsideCooldown(UUID userId) {
        OffsetDateTime createdAt =
                OffsetDateTime.now().minusMinutes(2);

        jdbcClient.sql("""
            UPDATE email_verification_tokens
            SET created_at = :createdAt,
                expires_at = :expiresAt
            WHERE user_id = :userId
            """)
                .param("createdAt", createdAt)
                .param("expiresAt", createdAt.plusHours(24))
                .param("userId", userId)
                .update();
    }

    private void performResendRequest(String email) throws Exception {
        String requestBody = """
            {
                "email": "%s"
            }
            """.formatted(email);

        mockMvc.perform(post(RESEND_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value(RESEND_MESSAGE));
    }

    private long countAuthSessions(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }

    private long countRefreshTokens(UUID userId) {
        return jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens rt
            JOIN auth_sessions s ON s.id = rt.session_id
            WHERE s.user_id = :userId
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();
    }


    @Test
    void login_multipleRequests_createIndependentSessions()
            throws Exception {

        String email = generateLoginEmail();

        UUID userId = registerVerifiedUser(email);

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();

        String firstResponseBody =
                performLoginRequest(email, LOGIN_PASSWORD)
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();

        assertThat(countAuthSessions(userId)).isEqualTo(1);
        assertThat(countRefreshTokens(userId)).isEqualTo(1);

        String secondResponseBody =
                performLoginRequest(email, LOGIN_PASSWORD)
                        .andExpect(status().isOk())
                        .andReturn()
                        .getResponse()
                        .getContentAsString();

        String firstRawToken = objectMapper
                .readTree(firstResponseBody)
                .get("refreshToken")
                .asText();

        String secondRawToken = objectMapper
                .readTree(secondResponseBody)
                .get("refreshToken")
                .asText();

        assertThat(firstRawToken)
                .isNotEqualTo(secondRawToken);

        String firstHash = hashRefreshToken(firstRawToken);
        String secondHash = hashRefreshToken(secondRawToken);

        assertThat(countAuthSessions(userId)).isEqualTo(2);
        assertThat(countRefreshTokens(userId)).isEqualTo(2);

        List<UUID> sessionIds = jdbcClient.sql("""
            SELECT id
            FROM auth_sessions
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(UUID.class)
                .list();

        assertThat(sessionIds)
                .hasSize(2)
                .doesNotHaveDuplicates();

        List<String> tokenHashes = jdbcClient.sql("""
            SELECT rt.token_hash
            FROM auth_refresh_tokens rt
            JOIN auth_sessions s ON s.id = rt.session_id
            WHERE s.user_id = :userId
            """)
                .param("userId", userId)
                .query(String.class)
                .list();

        assertThat(tokenHashes)
                .containsExactlyInAnyOrder(firstHash, secondHash);

        List<UUID> tokenSessionIds = jdbcClient.sql("""
            SELECT rt.session_id
            FROM auth_refresh_tokens rt
            JOIN auth_sessions s ON s.id = rt.session_id
            WHERE s.user_id = :userId
            """)
                .param("userId", userId)
                .query(UUID.class)
                .list();

        assertThat(tokenSessionIds)
                .containsExactlyInAnyOrderElementsOf(sessionIds);

        long activeSessionCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_sessions
            WHERE user_id = :userId
                AND revoked_at IS NULL
                AND expires_at > CURRENT_TIMESTAMP
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(activeSessionCount).isEqualTo(2);

        long activeTokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM auth_refresh_tokens rt
            JOIN auth_sessions s ON s.id = rt.session_id
            WHERE s.user_id = :userId
                AND rt.consumed_at IS NULL
                AND rt.expires_at > CURRENT_TIMESTAMP
            """)
                .param("userId", userId)
                .query(Long.class)
                .single();

        assertThat(activeTokenCount).isEqualTo(2);
    }



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


    @Test
    void register_whenEmailDeliveryFails_stillReturns201()
            throws Exception {

        String email = "delivery-failure-" + UUID.randomUUID()
                + "@example.com";

        doThrow(new IllegalStateException("Simulated delivery failure"))
                .when(emailSender)
                .sendVerificationEmail(
                        anyString(),
                        anyString()
                );

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
    }

    @Test
    void resendVerification_eligibleUser_returns200AndSendsEmail()
            throws Exception {

        String email = UUID.randomUUID() + "@example.com";

        UUID userId = registerUser(email);
        moveTokensOutsideCooldown(userId);

        performResendRequest(email);

        verify(emailSender, times(1))
                .sendVerificationEmail(eq(email), anyString());
    }

    @Test
    void resendVerification_unknownEmail_returns200()
            throws Exception {

        String email = UUID.randomUUID() + "@example.com";

        performResendRequest(email);

        verifyNoInteractions(emailSender);
    }

    @Test
    void resendVerification_verifiedUser_returns200()
            throws Exception {

        String email = UUID.randomUUID() + "@example.com";

        UUID userId = registerUser(email);

        String rawToken = verificationService.issueToken(userId);

        moveTokensOutsideCooldown(userId);

        verificationService.verifyToken(rawToken);

        performResendRequest(email);

        verifyNoInteractions(emailSender);
    }

    @Test
    void resendVerification_withinCooldown_returns200()
            throws Exception {

        String email = UUID.randomUUID() + "@example.com";

        registerUser(email);

        performResendRequest(email);

        verifyNoInteractions(emailSender);
    }

    @Test
    void resendVerification_invalidEmail_returns400()
            throws Exception {

        mockMvc.perform(post(RESEND_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                            {
                                "email": "invalid-email"
                            }
                            """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_RESEND_VERIFICATION"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid email format"));

        verifyNoInteractions(emailSender);
    }

    @Test
    void resendVerification_missingEmail_returns400()
            throws Exception {

        mockMvc.perform(post(RESEND_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_RESEND_VERIFICATION"))
                .andExpect(jsonPath("$.message")
                        .value("Email is required"));

        verifyNoInteractions(emailSender);
    }

    @Test
    void resendVerification_emailDeliveryFails_stillReturns200()
            throws Exception {

        String email = UUID.randomUUID() + "@example.com";

        UUID userId = registerUser(email);
        moveTokensOutsideCooldown(userId);

        doThrow(new IllegalStateException("Simulated delivery failure"))
                .when(emailSender)
                .sendVerificationEmail(eq(email), anyString());

        performResendRequest(email);

        verify(emailSender, times(1))
                .sendVerificationEmail(eq(email), anyString());

        Integer tokenCount = jdbcClient.sql("""
            SELECT COUNT(*)
            FROM email_verification_tokens
            WHERE user_id = :userId
            """)
                .param("userId", userId)
                .query(Integer.class)
                .single();

        assertThat(tokenCount).isEqualTo(2);
    }



    @Test
    void login_withValidCredentials_returns200AndPersistsTokens()
            throws Exception {

        String email = generateLoginEmail();

        UUID userId = registerVerifiedUser(email);

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();

        String responseBody = performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshTokenExpiresAt").isString())
                .andExpect(jsonPath("$.sessionExpiresAt").isString())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var response = objectMapper.readTree(responseBody);

        String rawToken = response.get("refreshToken").asText();

        String expectedHash = hashRefreshToken(rawToken);

        Instant refreshTokenExpiresAt = Instant.parse(
                response.get("refreshTokenExpiresAt").asText()
        );

        Instant sessionExpiresAt = Instant.parse(
                response.get("sessionExpiresAt").asText()
        );

        assertThat(countAuthSessions(userId)).isEqualTo(1);
        assertThat(countRefreshTokens(userId)).isEqualTo(1);

        jdbcClient.sql("""
            SELECT
                s.user_id,
                s.created_at AS session_created_at,
                s.expires_at AS session_expires_at,
                s.revoked_at,
                rt.token_hash,
                rt.created_at AS token_created_at,
                rt.expires_at AS token_expires_at,
                rt.consumed_at
            FROM auth_sessions s
            JOIN auth_refresh_tokens rt
                ON rt.session_id = s.id
            WHERE s.user_id = :userId
            """)
                .param("userId", userId)
                .query((rs, rowNum) -> {
                    assertThat(rs.getObject("user_id", UUID.class))
                            .isEqualTo(userId);

                    assertThat(rs.getString("token_hash"))
                            .isEqualTo(expectedHash)
                            .isNotEqualTo(rawToken)
                            .hasSize(64);

                    Instant sessionCreatedAt = rs.getObject(
                            "session_created_at",
                            OffsetDateTime.class
                    ).toInstant();

                    Instant tokenCreatedAt = rs.getObject(
                            "token_created_at",
                            OffsetDateTime.class
                    ).toInstant();

                    assertThat(tokenCreatedAt)
                            .isEqualTo(sessionCreatedAt);

                    assertThat(rs.getObject(
                            "session_expires_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(sessionExpiresAt);

                    assertThat(rs.getObject(
                            "token_expires_at",
                            OffsetDateTime.class
                    ).toInstant()).isEqualTo(refreshTokenExpiresAt);

                    assertThat(rs.getObject("revoked_at")).isNull();

                    assertThat(rs.getObject("consumed_at")).isNull();

                    return true;
                })
                .single();
    }



    @Test
    void login_returnsCorrectResponseStructure() throws Exception {
        String email = generateLoginEmail();

        registerVerifiedUser(email);

        String responseBody = performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(
                        MediaType.APPLICATION_JSON
                ))
                .andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").isNumber())
                .andExpect(jsonPath("$.refreshToken").isString())
                .andExpect(jsonPath("$.refreshTokenExpiresAt").isString())
                .andExpect(jsonPath("$.sessionExpiresAt").isString())
                .andExpect(jsonPath("$.password").doesNotExist())
                .andExpect(jsonPath("$.passwordHash").doesNotExist())
                .andExpect(jsonPath("$.tokenHash").doesNotExist())
                .andExpect(jsonPath("$.sessionId").doesNotExist())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var response = objectMapper.readTree(responseBody);

        assertThat(response.size()).isEqualTo(6);

        assertThat(response.get("refreshToken").asText())
                .hasSize(43)
                .matches("[A-Za-z0-9_-]{43}");

        Instant refreshTokenExpiresAt = Instant.parse(
                response.get("refreshTokenExpiresAt").asText()
        );

        Instant sessionExpiresAt = Instant.parse(
                response.get("sessionExpiresAt").asText()
        );

        assertThat(refreshTokenExpiresAt)
                .isAfter(Instant.now())
                .isBeforeOrEqualTo(sessionExpiresAt);

        assertThat(sessionExpiresAt)
                .isAfter(Instant.now());
    }


    @Test
    void login_returnsValidJwtAccessToken() throws Exception {
        String email = generateLoginEmail();

        UUID userId = registerVerifiedUser(email);

        String responseBody = performLoginRequest(
                email,
                LOGIN_PASSWORD
        )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        String accessToken = objectMapper
                .readTree(responseBody)
                .get("accessToken")
                .asText();

        Jwt decoded = jwtDecoder.decode(accessToken);

        assertThat(decoded.getSubject())
                .isEqualTo(userId.toString());

        assertThat(decoded.getClaimAsString(JwtClaimNames.ISS))
                .isEqualTo("ping-backend");

        assertThat(decoded.getAudience())
                .containsExactly("ping-api");

        assertThat(decoded.getHeaders().get("alg"))
                .isEqualTo("HS256");

        assertThat(Duration.between(
                decoded.getIssuedAt(),
                decoded.getExpiresAt()
        )).isEqualTo(Duration.ofMinutes(15));
    }

    @Test
    void login_normalizesEmailBeforeAuthentication() throws Exception {
        String email = generateLoginEmail();

        registerVerifiedUser(email);

        String rawEmail = "  "
                + email.toUpperCase(java.util.Locale.ROOT)
                + "  ";

        performLoginRequest(rawEmail, LOGIN_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty());
    }


    @Test
    void login_withIncorrectPassword_returns401() throws Exception {
        String email = generateLoginEmail();

        UUID userId = registerVerifiedUser(email);

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();

        performLoginRequest(email, "wrong-password")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid email or password"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();
    }


    @Test
    void login_withUnknownEmail_returns401() throws Exception {
        String email = generateLoginEmail();

        performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid email or password"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }


    @Test
    void login_whenEmailNotVerified_returns403() throws Exception {
        String email = generateLoginEmail();

        UUID userId = registerUser(email);

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();

        performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code")
                        .value("EMAIL_NOT_VERIFIED"))
                .andExpect(jsonPath("$.message")
                        .value("Email address has not been verified"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());

        assertThat(countAuthSessions(userId)).isZero();
        assertThat(countRefreshTokens(userId)).isZero();
    }


    @Test
    void login_whenEmailNotVerifiedAndPasswordIncorrect_returns401()
            throws Exception {

        String email = generateLoginEmail();

        registerUser(email);

        performLoginRequest(email, "wrong-password")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid email or password"))
                .andExpect(jsonPath("$.accessToken").doesNotExist())
                .andExpect(jsonPath("$.refreshToken").doesNotExist());
    }

    @Test
    void login_withInvalidEmail_returns400() throws Exception {
        performLoginRequest("invalid-email", LOGIN_PASSWORD)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_LOGIN_REQUEST"))
                .andExpect(jsonPath("$.message")
                        .value("Invalid email format"));
    }

    @Test
    void login_withMissingEmail_returns400() throws Exception {
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {
                            "password": "password123"
                        }
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_LOGIN_REQUEST"))
                .andExpect(jsonPath("$.message")
                        .value("Email is required"));
    }

    @Test
    void login_withMissingPassword_returns400() throws Exception {
        mockMvc.perform(post(LOGIN_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                        {
                            "email": "user@example.com"
                        }
                        """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_LOGIN_REQUEST"))
                .andExpect(jsonPath("$.message")
                        .value("Password is required"));
    }

    @Test
    void login_withBlankPassword_returns400() throws Exception {
        performLoginRequest("user@example.com", "   ")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_LOGIN_REQUEST"))
                .andExpect(jsonPath("$.message")
                        .value("Password is required"));
    }

    @Test
    void login_withPasswordExceeding72Bytes_returns400()
            throws Exception {

        String password = "a".repeat(73);

        performLoginRequest("user@example.com", password)
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_LOGIN_REQUEST"))
                .andExpect(jsonPath("$.message")
                        .value("Password must not exceed 72 bytes"));
    }

    @Test
    void login_successfulResponse_disablesCaching() throws Exception {
        String email = generateLoginEmail();

        registerVerifiedUser(email);

        performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isOk())
                .andExpect(header().string(
                        HttpHeaders.CACHE_CONTROL,
                        "no-store"
                ))
                .andExpect(header().string(
                        HttpHeaders.PRAGMA,
                        "no-cache"
                ));
    }


    @Test
    void login_successfulRequest_doesNotCreateHttpSession()
            throws Exception {

        String email = generateLoginEmail();

        registerVerifiedUser(email);

        var result = performLoginRequest(email, LOGIN_PASSWORD)
                .andExpect(status().isOk())
                .andReturn();

        assertThat(result.getRequest().getSession(false))
                .isNull();
    }


}
