package com.ping.backend.config;

import com.ping.backend.config.properties.JwtProperties;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtConfigTest {

    private final JwtConfig jwtConfig = new JwtConfig();

    private final String issuer = "ping-backend";
    private final String audience = "ping-api";
    private final Duration accessTokenTtl = Duration.ofMinutes(15);

    private String createSecret(int byteLength) {
        return Base64.getEncoder()
                .encodeToString(new byte[byteLength]);
    }

    private JwtProperties createProperties(
            String secret,
            Duration ttl
    ) {
        return new JwtProperties(
                secret,
                issuer,
                audience,
                ttl
        );
    }

    @Test
    void validSecret_createsSecretKey() {
        String secret = createSecret(32);

        JwtProperties properties =
                createProperties(secret, accessTokenTtl);

        SecretKey key = jwtConfig.jwtSecretKey(properties);

        assertThat(key.getAlgorithm()).isEqualTo("HmacSHA256");
        assertThat(key.getEncoded()).hasSize(32);
        assertThat(key.getEncoded())
                .isEqualTo(Base64.getDecoder().decode(secret));
    }

    @Test
    void invalidBase64_throwsException() {
        JwtProperties properties =
                createProperties("invalid-base64!!!", accessTokenTtl);

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT secret must be valid Base64");
    }

    @Test
    void emptySecret_throwsException() {
        JwtProperties properties =
                createProperties("", accessTokenTtl);

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT secret must contain exactly 32 bytes");
    }

    @Test
    void shortSecret_throwsException() {
        JwtProperties properties =
                createProperties(createSecret(31), accessTokenTtl);

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT secret must contain exactly 32 bytes");
    }

    @Test
    void longSecret_throwsException() {
        JwtProperties properties =
                createProperties(createSecret(33), accessTokenTtl);

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT secret must contain exactly 32 bytes");
    }

    @Test
    void zeroTtl_throwsException() {
        JwtProperties properties =
                createProperties(createSecret(32), Duration.ZERO);

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT access token TTL must be positive");
    }

    @Test
    void negativeTtl_throwsException() {
        JwtProperties properties =
                createProperties(
                        createSecret(32),
                        Duration.ofMinutes(-1)
                );

        assertThatThrownBy(() ->
                jwtConfig.jwtSecretKey(properties)
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("JWT access token TTL must be positive");
    }

    @Test
    void propertiesToString_doesNotExposeSecret() {
        String secret = createSecret(32);

        JwtProperties properties =
                createProperties(secret, accessTokenTtl);

        String result = properties.toString();

        assertThat(result)
                .doesNotContain(secret)
                .contains("REDACTED")
                .contains(issuer)
                .contains(audience);
    }


}