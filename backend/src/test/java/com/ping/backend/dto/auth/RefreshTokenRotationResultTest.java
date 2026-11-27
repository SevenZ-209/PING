
package com.ping.backend.dto.auth;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenRotationResultTest {

    @Test
    void toString_doesNotExposeRawRefreshToken() {
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();

        String rawToken = "A".repeat(43);

        Instant refreshTokenExpiresAt =
                Instant.parse("2026-12-01T00:00:00Z");

        Instant sessionExpiresAt =
                Instant.parse("2027-01-30T00:00:00Z");

        RefreshTokenRotationResult result =
                new RefreshTokenRotationResult(
                        userId,
                        sessionId,
                        rawToken,
                        refreshTokenExpiresAt,
                        sessionExpiresAt
                );

        assertThat(result.toString())
                .doesNotContain(rawToken)
                .contains("rawRefreshToken=REDACTED")
                .contains("userId=" + userId)
                .contains("sessionId=" + sessionId)
                .contains("refreshTokenExpiresAt=" + refreshTokenExpiresAt)
                .contains("sessionExpiresAt=" + sessionExpiresAt);
    }
}
