
package com.ping.backend.dto.auth;

import java.time.Instant;
import java.util.UUID;

public record RefreshTokenIssuanceResult(
        String rawRefreshToken,
        UUID sessionId,
        Instant refreshTokenExpiresAt,
        Instant sessionExpiresAt
) {

    @Override
    public String toString() {
        return "RefreshTokenIssuanceResult[rawRefreshToken=REDACTED"
                + ", sessionId=" + sessionId
                + ", refreshTokenExpiresAt=" + refreshTokenExpiresAt
                + ", sessionExpiresAt=" + sessionExpiresAt
                + "]";
    }
}
