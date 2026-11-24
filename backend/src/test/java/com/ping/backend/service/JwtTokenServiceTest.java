package com.ping.backend.service;

import com.ping.backend.config.JwtConfig;
import com.ping.backend.config.properties.JwtProperties;
import com.ping.backend.dto.auth.AccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.*;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenServiceTest {

    private final JwtConfig jwtConfig = new JwtConfig();

    private final String secret = Base64.getEncoder()
            .encodeToString(new byte[32]);

    private final String issuer = "ping-backend";
    private final String audience = "ping-api";
    private final Duration ttl = Duration.ofMinutes(15);

    private final UUID userId = UUID.randomUUID();

    private JwtTokenService jwtTokenService;
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        JwtProperties properties = createProperties(ttl);

        SecretKey secretKey =
                jwtConfig.jwtSecretKey(properties);

        JwtEncoder jwtEncoder =
                jwtConfig.jwtEncoder(secretKey);

        jwtDecoder =
                jwtConfig.jwtDecoder(secretKey, properties);

        jwtTokenService =
                new JwtTokenService(jwtEncoder, properties);
    }

    private JwtProperties createProperties(Duration duration) {
        return new JwtProperties(
                secret,
                issuer,
                audience,
                duration
        );
    }

    private Jwt generateAndDecodeToken() {
        AccessToken accessToken =
                jwtTokenService.generateAccessToken(userId);

        return jwtDecoder.decode(accessToken.token());
    }

    @Test
    void generateAccessToken_returnsValidToken() {
        AccessToken accessToken =
                jwtTokenService.generateAccessToken(userId);

        assertThat(accessToken).isNotNull();
        assertThat(accessToken.token()).isNotBlank();

        Jwt decoded = jwtDecoder.decode(accessToken.token());

        assertThat(decoded).isNotNull();
    }

    @Test
    void generatedToken_containsCorrectSubject() {
        Jwt decoded = generateAndDecodeToken();

        assertThat(decoded.getSubject())
                .isEqualTo(userId.toString());
    }

    @Test
    void generatedToken_containsCorrectIssuer() {
        Jwt decoded = generateAndDecodeToken();

        assertThat(decoded.getClaimAsString(JwtClaimNames.ISS))
                .isEqualTo(issuer);
    }

    @Test
    void generatedToken_containsCorrectAudience() {
        Jwt decoded = generateAndDecodeToken();

        assertThat(decoded.getAudience())
                .containsExactly(audience);
    }

    @Test
    void generatedToken_usesHs256Algorithm() {
        Jwt decoded = generateAndDecodeToken();

        assertThat(decoded.getHeaders().get("alg"))
                .isEqualTo("HS256");
    }

    @Test
    void generatedToken_containsCorrectTimestamps() {
        Instant before = Instant.now()
                .truncatedTo(ChronoUnit.SECONDS);

        Jwt decoded = generateAndDecodeToken();

        Instant after = Instant.now()
                .truncatedTo(ChronoUnit.SECONDS);

        assertThat(decoded.getIssuedAt())
                .isBetween(before, after);

        assertThat(decoded.getExpiresAt())
                .isEqualTo(decoded.getIssuedAt().plus(ttl));

        assertThat(Duration.between(
                decoded.getIssuedAt(),
                decoded.getExpiresAt()
        )).isEqualTo(ttl);
    }

    @Test
    void generateAccessToken_returnsCorrectExpiresIn() {
        AccessToken accessToken =
                jwtTokenService.generateAccessToken(userId);

        assertThat(accessToken.expiresIn())
                .isEqualTo(900L);
    }

    @Test
    void generateAccessToken_usesConfiguredTtl() {
        Duration customTtl = Duration.ofMinutes(5);

        JwtProperties properties =
                createProperties(customTtl);

        SecretKey secretKey =
                jwtConfig.jwtSecretKey(properties);

        JwtEncoder encoder =
                jwtConfig.jwtEncoder(secretKey);

        JwtTokenService customService =
                new JwtTokenService(encoder, properties);

        AccessToken accessToken =
                customService.generateAccessToken(userId);

        Jwt decoded = jwtDecoder.decode(accessToken.token());

        assertThat(accessToken.expiresIn())
                .isEqualTo(300L);

        assertThat(Duration.between(
                decoded.getIssuedAt(),
                decoded.getExpiresAt()
        )).isEqualTo(customTtl);
    }

    @Test
    void generatedToken_containsOnlyRequiredClaims() {
        Jwt decoded = generateAndDecodeToken();

        assertThat(decoded.getClaims().keySet())
                .containsExactlyInAnyOrder(
                        JwtClaimNames.SUB,
                        JwtClaimNames.ISS,
                        JwtClaimNames.AUD,
                        JwtClaimNames.IAT,
                        JwtClaimNames.EXP
                );
    }

    @Test
    void generateAccessToken_withNullUserId_throwsException() {
        assertThatThrownBy(() ->
                jwtTokenService.generateAccessToken(null)
        )
                .isInstanceOf(NullPointerException.class)
                .hasMessage("User ID is required");
    }

    @Test
    void accessTokenToString_doesNotExposeToken() {
        AccessToken accessToken =
                jwtTokenService.generateAccessToken(userId);

        assertThat(accessToken.toString())
                .doesNotContain(accessToken.token())
                .contains("REDACTED")
                .contains("expiresIn=900");
    }
}