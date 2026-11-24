
package com.ping.backend.repository;

import com.ping.backend.entity.EmailVerificationToken;

import java.util.Optional;
import java.util.UUID;

public interface EmailVerificationTokenQueries {

    Optional<EmailVerificationToken> findByTokenHashForUpdate(
            String tokenHash
    );

    Optional<UUID> findUserIdByTokenHash(String tokenHash);
}
