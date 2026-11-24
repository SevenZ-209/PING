package com.ping.backend.repository;

import com.ping.backend.entity.EmailVerificationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.UUID;
import java.util.Optional;

public interface EmailVerificationTokenRepository
        extends JpaRepository<EmailVerificationToken, UUID>,
        EmailVerificationTokenQueries {

    List<EmailVerificationToken>
    findByUserIdAndConsumedAtIsNullAndInvalidatedAtIsNull(UUID userId);

    Optional<EmailVerificationToken>
    findFirstByUserIdOrderByCreatedAtDesc(UUID userId);
}

