package com.ping.backend.config;

import com.ping.backend.config.properties.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtEncoderDecoderTest {

    private final JwtConfig jwtConfig = new JwtConfig();

    private final String issuer = "ping-backend";
    private final String audience = "ping-api";
    private final String userId = UUID.randomUUID().toString();
    private final Duration ttl = Duration.ofMinutes(15);

    private JwtEncoder jwtEncoder;
    private JwtDecoder jwtDecoder;

    @BeforeEach
    void setUp() {
        String secret = Base64.getEncoder()
                .encodeToString(new byte[32]);

        JwtProperties properties = new JwtProperties(
                secret,
                issuer,
                audience,
                ttl
        );

        SecretKey secretKey = jwtConfig.jwtSecretKey(properties);

        jwtEncoder = jwtConfig.jwtEncoder(secretKey);
        jwtDecoder = jwtConfig.jwtDecoder(secretKey, properties);
    }

    private JwtClaimsSet.Builder createClaims() {
        Instant now = Instant.now();

        return JwtClaimsSet.builder()
                .subject(userId)
                .issuer(issuer)
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plus(ttl));
    }

    private String encode(JwtEncoder encoder, JwtClaimsSet claims) {
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

    @Test
    void validToken_isDecodedSuccessfully() {
        String token = encode(createClaims().build());

        Jwt decoded = jwtDecoder.decode(token);

        assertThat(decoded.getSubject()).isEqualTo(userId);
        assertThat(decoded.getClaimAsString(JwtClaimNames.ISS))
                .isEqualTo(issuer);
        assertThat(decoded.getAudience()).containsExactly(audience);
        assertThat(decoded.getHeaders().get("alg")).isEqualTo("HS256");
        assertThat(decoded.getIssuedAt()).isNotNull();
        assertThat(decoded.getExpiresAt()).isNotNull();

        assertThat(Duration.between(
                decoded.getIssuedAt(),
                decoded.getExpiresAt()
        )).isEqualTo(ttl);
    }

    @Test
    void expiredToken_isRejected() {
        Instant now = Instant.now();

        JwtClaimsSet claims = createClaims()
                .issuedAt(now.minus(Duration.ofMinutes(16)))
                .expiresAt(now.minus(Duration.ofMinutes(1)))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void tokenSignedWithDifferentKey_isRejected() {
        byte[] differentKeyBytes = new byte[32];
        differentKeyBytes[0] = 1;

        String differentSecret = Base64.getEncoder()
                .encodeToString(differentKeyBytes);

        JwtProperties properties = new JwtProperties(
                differentSecret,
                issuer,
                audience,
                ttl
        );

        SecretKey differentKey = jwtConfig.jwtSecretKey(properties);

        JwtEncoder differentEncoder =
                jwtConfig.jwtEncoder(differentKey);

        String token = encode(
                differentEncoder,
                createClaims().build()
        );

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void wrongIssuer_isRejected() {
        JwtClaimsSet claims = createClaims()
                .issuer("another-backend")
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void wrongAudience_isRejected() {
        JwtClaimsSet claims = createClaims()
                .audience(List.of("another-api"))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void missingExpiration_isRejected() {
        JwtClaimsSet claims = createClaims()
                .claims(values -> values.remove(JwtClaimNames.EXP))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void tokenNotYetValid_isRejected() {
        JwtClaimsSet claims = createClaims()
                .notBefore(Instant.now().plusSeconds(30))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void malformedToken_isRejected() {
        assertThatThrownBy(() ->
                jwtDecoder.decode("invalid-jwt-token")
        ).isInstanceOf(JwtException.class);
    }

    @Test
    void tamperedPayload_isRejected() {
        String token = encode(createClaims().build());

        String[] parts = token.split("\\.");

        String payload = new String(
                Base64.getUrlDecoder().decode(parts[1]),
                StandardCharsets.UTF_8
        );

        String modifiedPayload = payload.replace(
                userId,
                UUID.randomUUID().toString()
        );

        assertThat(modifiedPayload).isNotEqualTo(payload);

        parts[1] = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(
                        modifiedPayload.getBytes(StandardCharsets.UTF_8)
                );

        String tamperedToken = String.join(".", parts);

        assertThatThrownBy(() -> jwtDecoder.decode(tamperedToken))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void missingAudience_isRejected() {
        JwtClaimsSet claims = createClaims()
                .claims(values -> values.remove(JwtClaimNames.AUD))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void missingIssuer_isRejected() {
        JwtClaimsSet claims = createClaims()
                .claims(values -> values.remove(JwtClaimNames.ISS))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void decode_withMissingSubject_throwsException() {
        JwtClaimsSet claims = createClaims()
                .claims(values -> values.remove(JwtClaimNames.SUB))
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void decode_withEmptySubject_throwsException() {
        JwtClaimsSet claims = createClaims()
                .subject("")
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void decode_withBlankSubject_throwsException() {
        JwtClaimsSet claims = createClaims()
                .subject("   ")
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void decode_withInvalidUuidSubject_throwsException() {
        JwtClaimsSet claims = createClaims()
                .subject("user@example.com")
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void decode_withNonCanonicalUuidSubject_throwsException() {
        JwtClaimsSet claims = createClaims()
                .subject("1-1-1-1-1")
                .build();

        String token = encode(claims);

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

    @Test
    void decode_withMissingIssuedAt_throwsException()
            throws Exception {

        JwtClaimsSet claims = createClaims()
                .claims(values -> values.remove(JwtClaimNames.IAT))
                .build();

        String token = encode(claims);

        var rawClaims = com.nimbusds.jwt.SignedJWT
                .parse(token)
                .getJWTClaimsSet();

        assertThat(rawClaims.getIssueTime()).isNull();

        assertThatThrownBy(() -> jwtDecoder.decode(token))
                .isInstanceOf(JwtException.class);
    }

}