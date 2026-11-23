package com.ping.backend.repository;

import com.ping.backend.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;

public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, UUID> {

    List<EmailVerificationToken>
    findByUserIdAndConsumedAtIsNullAndInvalidatedAtIsNull(UUID userId);
}

