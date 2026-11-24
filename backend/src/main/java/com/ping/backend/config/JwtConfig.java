package com.ping.backend.config;

import com.ping.backend.config.properties.JwtProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import java.time.Instant;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import java.util.Map;

@Configuration
@EnableConfigurationProperties(JwtProperties.class)
public class JwtConfig {

    @Bean
    public SecretKey jwtSecretKey(JwtProperties properties) {
        byte[] keyBytes;

        try {
            keyBytes = Base64.getDecoder()
                    .decode(properties.secret());
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException(
                    "JWT secret must be valid Base64"
            );
        }

        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "JWT secret must contain exactly 32 bytes"
            );
        }

        if (properties.accessTokenTtl().isZero()
                || properties.accessTokenTtl().isNegative()) {
            throw new IllegalStateException(
                    "JWT access token TTL must be positive"
            );
        }

        return new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    @Bean
    public JwtEncoder jwtEncoder(SecretKey jwtSecretKey) {
        return NimbusJwtEncoder
                .withSecretKey(jwtSecretKey)
                .algorithm(MacAlgorithm.HS256)
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(
            SecretKey jwtSecretKey,
            JwtProperties properties
    ) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withSecretKey(jwtSecretKey)
                .macAlgorithm(MacAlgorithm.HS256)
                .build();

        MappedJwtClaimSetConverter defaultConverter =
                MappedJwtClaimSetConverter.withDefaults(Map.of());

        decoder.setClaimSetConverter(claims -> {
            if (claims.get(JwtClaimNames.IAT) == null) {
                throw new BadJwtException(
                        "JWT issued-at claim is required"
                );
            }

            return defaultConverter.convert(claims);
        });

        OAuth2TokenValidator<Jwt> validator =
                new DelegatingOAuth2TokenValidator<>(
                        new JwtTimestampValidator(Duration.ZERO),
                        new JwtIssuerValidator(properties.issuer()),
                        new JwtAudienceValidator(properties.audience()),
                        new JwtClaimValidator<Instant>(
                                JwtClaimNames.EXP,
                                expiration -> expiration != null
                        ),
                        new JwtClaimValidator<String>(
                                JwtClaimNames.SUB,
                                this::isValidUserId
                        ),
                        new JwtClaimValidator<Instant>(
                                JwtClaimNames.IAT,
                                issuedAt -> issuedAt != null
                        )
                );

        decoder.setJwtValidator(validator);

        return decoder;
    }

    private boolean isValidUserId(String subject) {
        if (subject == null || subject.isBlank()) {
            return false;
        }

        try {
            UUID userId = UUID.fromString(subject);

            return userId.toString().equalsIgnoreCase(subject);
        } catch (IllegalArgumentException exception) {
            return false;
        }
    }
}