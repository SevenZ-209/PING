package com.ping.backend.config.properties;

import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Validated
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        @NotNull Duration refreshTokenTtl,
        @NotNull Duration sessionTtl
) {
    public AuthProperties {
        if (refreshTokenTtl == null) {
            throw new IllegalArgumentException(
                    "Refresh token TTL is required"
            );
        }

        if (sessionTtl == null) {
            throw new IllegalArgumentException(
                    "Session TTL is required"
            );
        }

        if (refreshTokenTtl.isZero()
                || refreshTokenTtl.isNegative()) {
            throw new IllegalArgumentException(
                    "Refresh token TTL must be positive"
            );
        }

        if (sessionTtl.isZero()
                || sessionTtl.isNegative()) {
            throw new IllegalArgumentException(
                    "Session TTL must be positive"
            );
        }

        if (sessionTtl.compareTo(refreshTokenTtl) < 0) {
            throw new IllegalArgumentException(
                    "Session TTL must be greater than or equal to refresh token TTL"
            );
        }
    }
}