
package com.ping.backend.auth;

import java.time.Instant;
import java.util.UUID;

public interface EmailVerificationTokenRepository {

    void lockUser(UUID userId);

    void invalidateActiveTokens(UUID userId, Instant now);

    void save(
            UUID id,
            UUID userId,
            String tokenHash,
            Instant createdAt,
            Instant expiresAt
    );
}
