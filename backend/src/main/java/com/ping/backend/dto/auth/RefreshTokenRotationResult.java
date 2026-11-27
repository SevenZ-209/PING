
package com.ping.backend.dto.auth;

import java.time.Instant;
import java.util.UUID;

public record RefreshTokenRotationResult(
        UUID userId,
        UUID sessionId,
        String rawRefreshToken,
        Instant refreshTokenExpiresAt,
        Instant sessionExpiresAt
) {

    @Override
    public String toString() {
        return "RefreshTokenRotationResult[userId=" + userId
                + ", sessionId=" + sessionId
                + ", rawRefreshToken=REDACTED"
                + ", refreshTokenExpiresAt=" + refreshTokenExpiresAt
                + ", sessionExpiresAt=" + sessionExpiresAt
                + "]";
    }
}
