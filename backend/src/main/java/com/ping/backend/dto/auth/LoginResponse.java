
package com.ping.backend.dto.auth;

import java.time.Instant;

public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn,
        String refreshToken,
        Instant refreshTokenExpiresAt,
        Instant sessionExpiresAt
) {

    @Override
    public String toString() {
        return "LoginResponse[accessToken=REDACTED"
                + ", tokenType=" + tokenType
                + ", expiresIn=" + expiresIn
                + ", refreshToken=REDACTED"
                + ", refreshTokenExpiresAt=" + refreshTokenExpiresAt
                + ", sessionExpiresAt=" + sessionExpiresAt
                + "]";
    }
}
