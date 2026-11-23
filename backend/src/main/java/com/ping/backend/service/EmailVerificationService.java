
package com.ping.backend.service;
import com.ping.backend.repository.EmailVerificationTokenRepository;
import com.ping.backend.security.VerificationTokenGenerator;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class EmailVerificationService {

    private static final Duration TOKEN_TTL = Duration.ofHours(24);

    private final EmailVerificationTokenRepository repository;
    private final VerificationTokenGenerator tokenGenerator;

    public EmailVerificationService(
            EmailVerificationTokenRepository repository,
            VerificationTokenGenerator tokenGenerator
    ) {
        this.repository = repository;
        this.tokenGenerator = tokenGenerator;
    }

    @Transactional
    public String issueToken(UUID userId) {
        repository.lockUser(userId);

        Instant now = Instant.now();

        String rawToken = tokenGenerator.generate();
        String tokenHash = tokenGenerator.hash(rawToken);

        repository.invalidateActiveTokens(userId, now);

        repository.save(
                UUID.randomUUID(),
                userId,
                tokenHash,
                now,
                now.plus(TOKEN_TTL)
        );

        return rawToken;
    }
}
