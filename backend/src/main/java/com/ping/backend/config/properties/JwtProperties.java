package com.ping.backend.config.properties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
        @NotBlank String secret,
        @NotBlank String issuer,
        @NotBlank String audience,
        @NotNull Duration accessTokenTtl
) {
    @Override
    public String toString() {
        return "JwtProperties[secret=REDACTED, issuer=" + issuer
                + ", audience=" + audience
                + ", accessTokenTtl=" + accessTokenTtl + "]";
    }
}