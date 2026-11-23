
package com.ping.backend.service;

import com.ping.backend.entity.EmailVerificationToken;
import com.ping.backend.repository.EmailVerificationTokenRepository;
import com.ping.backend.repository.UserRepository;
import com.ping.backend.security.VerificationTokenGenerator;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class EmailVerificationService {

    private static final Duration TOKEN_TTL = Duration.ofHours(24);

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final VerificationTokenGenerator tokenGenerator;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokenRepository,
            UserRepository userRepository,
            VerificationTokenGenerator tokenGenerator
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @Transactional
    public String issueToken(UUID userId) {

        userRepository.findByIdForUpdate(userId)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        Instant now = Instant.now();

        String rawToken = tokenGenerator.generate();
        String tokenHash = tokenGenerator.hash(rawToken);

        var activeTokens = tokenRepository
                .findByUserIdAndConsumedAtIsNullAndInvalidatedAtIsNull(userId);

        for (EmailVerificationToken token : activeTokens) {
            token.invalidate(now);
        }

        tokenRepository.flush();

        EmailVerificationToken newToken = new EmailVerificationToken(
                UUID.randomUUID(),
                userId,
                tokenHash,
                now,
                now.plus(TOKEN_TTL)
        );

        tokenRepository.save(newToken);

        return rawToken;
    }
}
