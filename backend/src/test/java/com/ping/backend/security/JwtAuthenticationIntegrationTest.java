package com.ping.backend.security;

import com.ping.backend.config.JwtConfig;
import com.ping.backend.config.SecurityConfig;
import com.ping.backend.config.properties.JwtProperties;
import com.ping.backend.service.JwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.crypto.spec.SecretKeySpec;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;


@WebMvcTest(
        controllers = JwtAuthenticationIntegrationTest.TestController.class,
        properties = {
                "jwt.secret=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
                "jwt.issuer=ping-backend",
                "jwt.audience=ping-api",
                "jwt.access-token-ttl=15m"
        }
)
@Import({
        SecurityConfig.class,
        JwtConfig.class,
        JwtTokenService.class,
        RestAuthenticationEntryPoint.class,
        RestAccessDeniedHandler.class,
        JwtAuthenticationIntegrationTest.TestController.class
})
class JwtAuthenticationIntegrationTest {

    private static final String PROTECTED_URL =
            "/api/v1/test/protected";

    private static final String PRINCIPAL_URL =
            "/api/v1/test/principal";

    private static final String FORBIDDEN_URL =
            "/api/v1/test/forbidden";

    private static final String LOGIN_URL =
            "/api/v1/auth/login";

    private final UUID userId = UUID.randomUUID();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtProperties jwtProperties;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private JwtTokenService jwtTokenService;

    @RestController
    public static class TestController {

        @GetMapping(PROTECTED_URL)
        public Map<String, String> protectedEndpoint() {
            return Map.of("message", "Access granted");
        }

        @GetMapping(PRINCIPAL_URL)
        public Map<String, String> principalEndpoint(
                @AuthenticationPrincipal Jwt jwt
        ) {
            return Map.of("userId", jwt.getSubject());
        }

        @GetMapping(FORBIDDEN_URL)
        public void forbiddenEndpoint() {
            throw new AccessDeniedException("Access denied");
        }

        @PostMapping(LOGIN_URL)
        public Map<String, String> publicEndpoint() {
            return Map.of("message", "Public access granted");
        }
    }

    private String generateValidToken() {
        return jwtTokenService
                .generateAccessToken(userId)
                .token();
    }

    private JwtClaimsSet.Builder createClaims() {
        Instant now = Instant.now();

        return JwtClaimsSet.builder()
                .subject(userId.toString())
                .issuer(jwtProperties.issuer())
                .audience(List.of(jwtProperties.audience()))
                .issuedAt(now)
                .expiresAt(
                        now.plus(jwtProperties.accessTokenTtl())
                );
    }

    private String encode(
            JwtEncoder encoder,
            JwtClaimsSet claims
    ) {
        JwsHeader header = JwsHeader
                .with(MacAlgorithm.HS256)
                .build();

        return encoder.encode(
                JwtEncoderParameters.from(header, claims)
        ).getTokenValue();
    }

    private String encode(JwtClaimsSet claims) {
        return encode(jwtEncoder, claims);
    }

    private JwtEncoder createDifferentEncoder() {
        byte[] differentKeyBytes = Base64.getDecoder()
                .decode(jwtProperties.secret());

        differentKeyBytes[0] ^= 1;

        SecretKey differentKey = new SecretKeySpec(
                differentKeyBytes,
                "HmacSHA256"
        );

        return NimbusJwtEncoder
                .withSecretKey(differentKey)
                .algorithm(MacAlgorithm.HS256)
                .build();
    }

    private String tamperToken(String token) {
        String[] parts = token.split("\\.");

        String payload = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );

        String modifiedPayload = payload.replace(
                userId.toString(),
                UUID.randomUUID().toString()
        );

        assertThat(modifiedPayload).isNotEqualTo(payload);

        parts[1] = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        modifiedPayload.getBytes(
                                StandardCharsets.UTF_8
                        )
                );

        return String.join(".", parts);
    }

    private ResultActions performProtectedRequest(String token)
            throws Exception {

        return mockMvc.perform(
                get(PROTECTED_URL)
                        .header(
                                HttpHeaders.AUTHORIZATION,
                                "Bearer " + token
                        )
        );
    }

    @Test
    void validAccessToken_returns200() throws Exception {
        String token = generateValidToken();

        performProtectedRequest(token)
                .andExpect(status().isOk())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.message")
                        .value("Access granted"));
    }

    @Test
    void validAccessToken_exposesCorrectUserId() throws Exception {
        String token = generateValidToken();

        mockMvc.perform(
                        get(PRINCIPAL_URL)
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        "Bearer " + token
                                )
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId")
                        .value(userId.toString()));
    }

    @Test
    void validAccessToken_doesNotCreateSession() throws Exception {
        String token = generateValidToken();

        performProtectedRequest(token)
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(
                        result.getRequest().getSession(false)
                ).isNull());
    }

    @Test
    void authentication_doesNotPersistAcrossRequests()
            throws Exception {

        String token = generateValidToken();

        performProtectedRequest(token)
                .andExpect(status().isOk());

        mockMvc.perform(get(PROTECTED_URL))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code")
                        .value("UNAUTHORIZED"))
                .andExpect(result -> assertThat(
                        result.getRequest().getSession(false)
                ).isNull());
    }

    private void expectUnauthorized(ResultActions result)
            throws Exception {

        result.andExpect(status().isUnauthorized())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code")
                        .value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message")
                        .value("Authentication is required"))
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE,
                        matchesPattern("^Bearer(?:\\s+.*)?$")
                ));
    }

    @Test
    void missingAccessToken_returns401() throws Exception {
        expectUnauthorized(
                mockMvc.perform(get(PROTECTED_URL))
        );
    }

    @Test
    void malformedAccessToken_returns401() throws Exception {
        expectUnauthorized(
                performProtectedRequest("invalid-jwt-token")
        );
    }

    @Test
    void expiredAccessToken_returns401() throws Exception {
        Instant now = Instant.now();

        JwtClaimsSet claims = createClaims()
                .issuedAt(now.minus(Duration.ofMinutes(16)))
                .expiresAt(now.minus(Duration.ofMinutes(1)))
                .build();

        String token = encode(claims);

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }


    @Test
    void tamperedAccessToken_returns401() throws Exception {
        String originalToken = generateValidToken();

        String tamperedToken = tamperToken(originalToken);

        expectUnauthorized(
                performProtectedRequest(tamperedToken)
        );
    }

    @Test
    void accessTokenWithInvalidIssuer_returns401()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .issuer("another-backend")
                .build();

        String token = encode(claims);

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void accessTokenWithInvalidAudience_returns401()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .audience(List.of("another-api"))
                .build();

        String token = encode(claims);

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void accessTokenWithoutSubject_returns401()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .claims(values ->
                        values.remove(JwtClaimNames.SUB))
                .build();

        String token = encode(claims);

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void accessTokenWithInvalidUuidSubject_returns401()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .subject("user@example.com")
                .build();

        String token = encode(claims);

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void accessTokenWithoutIssuedAt_returns401()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .claims(values ->
                        values.remove(JwtClaimNames.IAT))
                .build();

        String token = encode(claims);

        var rawClaims = com.nimbusds.jwt.SignedJWT
                .parse(token)
                .getJWTClaimsSet();

        assertThat(rawClaims.getIssueTime()).isNull();

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void accessTokenSignedWithDifferentKey_returns401()
            throws Exception {

        JwtEncoder differentEncoder =
                createDifferentEncoder();

        assertThat(differentEncoder)
                .isNotSameAs(jwtEncoder);

        String token = encode(
                differentEncoder,
                createClaims().build()
        );

        expectUnauthorized(
                performProtectedRequest(token)
        );
    }

    @Test
    void authenticatedRequestWithAccessDenied_returns403()
            throws Exception {

        String token = generateValidToken();

        mockMvc.perform(
                        get(FORBIDDEN_URL)
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        "Bearer " + token
                                )
                )
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code")
                        .value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.message")
                        .value("Access denied"));
    }

    @Test
    void publicEndpointWithInvalidBearerToken_returns401()
            throws Exception {

        expectUnauthorized(
                mockMvc.perform(
                        post(LOGIN_URL)
                                .header(
                                        HttpHeaders.AUTHORIZATION,
                                        "Bearer invalid-jwt-token"
                                )
                )
        );
    }


}