package com.ping.backend.repository;

import com.ping.backend.entity.EmailVerificationToken;
import java.util.Optional;

public interface EmailVerificationTokenQueries {

    Optional<EmailVerificationToken> findByTokenHashForUpdate(
            String tokenHash
    );
}