package com.ping.backend.config.properties;

import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthPropertiesTest {

    private static final Duration REFRESH_TOKEN_TTL =
            Duration.ofDays(30);

    private static final Duration SESSION_TTL =
            Duration.ofDays(90);

    @Test
    void constructor_validTtls_createsProperties() {
        AuthProperties properties = new AuthProperties(
                REFRESH_TOKEN_TTL,
                SESSION_TTL
        );

        assertThat(properties.refreshTokenTtl())
                .isEqualTo(REFRESH_TOKEN_TTL);

        assertThat(properties.sessionTtl())
                .isEqualTo(SESSION_TTL);
    }

    @Test
    void constructor_equalTtls_createsProperties() {
        AuthProperties properties = new AuthProperties(
                REFRESH_TOKEN_TTL,
                REFRESH_TOKEN_TTL
        );

        assertThat(properties.refreshTokenTtl())
                .isEqualTo(REFRESH_TOKEN_TTL);

        assertThat(properties.sessionTtl())
                .isEqualTo(REFRESH_TOKEN_TTL);
    }

    @Test
    void constructor_nullRefreshTokenTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                null,
                SESSION_TTL
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Refresh token TTL is required");
    }

    @Test
    void constructor_nullSessionTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                REFRESH_TOKEN_TTL,
                null
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Session TTL is required");
    }

    @Test
    void constructor_zeroRefreshTokenTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                Duration.ZERO,
                SESSION_TTL
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Refresh token TTL must be positive");
    }

    @Test
    void constructor_negativeRefreshTokenTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                Duration.ofDays(-1),
                SESSION_TTL
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Refresh token TTL must be positive");
    }

    @Test
    void constructor_zeroSessionTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                REFRESH_TOKEN_TTL,
                Duration.ZERO
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Session TTL must be positive");
    }

    @Test
    void constructor_negativeSessionTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                REFRESH_TOKEN_TTL,
                Duration.ofDays(-1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Session TTL must be positive");
    }

    @Test
    void constructor_sessionTtlShorterThanRefreshTokenTtl_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> new AuthProperties(
                REFRESH_TOKEN_TTL,
                REFRESH_TOKEN_TTL.minusNanos(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "Session TTL must be greater than or equal to refresh token TTL"
                );
    }
}