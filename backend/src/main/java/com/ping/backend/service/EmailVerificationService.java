package com.ping.backend.service;

import com.ping.backend.exception.InvalidVerificationTokenException;
import com.ping.backend.entity.EmailVerificationToken;
import com.ping.backend.repository.EmailVerificationTokenRepository;
import com.ping.backend.repository.UserRepository;
import com.ping.backend.security.VerificationTokenGenerator;
import com.ping.backend.entity.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import com.ping.backend.dto.auth.ResendVerificationRequest;
import com.ping.backend.event.EmailVerificationRequested;
import com.ping.backend.validation.ResendVerificationValidator;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@Service
public class EmailVerificationService {

    private static final Duration TOKEN_TTL = Duration.ofHours(24);
    private static final Duration RESEND_COOLDOWN =
            Duration.ofSeconds(60);
    private final ResendVerificationValidator resendVerificationValidator;
    private final ApplicationEventPublisher eventPublisher;

    private final EmailVerificationTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final VerificationTokenGenerator tokenGenerator;

    public EmailVerificationService(
            EmailVerificationTokenRepository tokenRepository,
            UserRepository userRepository,
            VerificationTokenGenerator tokenGenerator,
            ResendVerificationValidator resendVerificationValidator,
            ApplicationEventPublisher eventPublisher
    ) {
        this.tokenRepository = tokenRepository;
        this.userRepository = userRepository;
        this.tokenGenerator = tokenGenerator;
        this.resendVerificationValidator = resendVerificationValidator;
        this.eventPublisher = eventPublisher;
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


    @Transactional
    public void verifyToken(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw new InvalidVerificationTokenException();
        }

        String tokenHash = tokenGenerator.hash(rawToken);

        UUID userId = tokenRepository
                .findUserIdByTokenHash(tokenHash)
                .orElseThrow(InvalidVerificationTokenException::new);

        User user = userRepository
                .findByIdForUpdate(userId)
                .orElseThrow(InvalidVerificationTokenException::new);

        EmailVerificationToken token = tokenRepository
                .findByTokenHashForUpdate(tokenHash)
                .orElseThrow(InvalidVerificationTokenException::new);

        Instant now = Instant.now();

        if (token.getConsumedAt() != null
                || token.getInvalidatedAt() != null
                || !token.getExpiresAt().isAfter(now)) {
            throw new InvalidVerificationTokenException();
        }

        user.verifyEmail(now);
        token.consume(now);
    }


    @Transactional
    public void resendVerification(ResendVerificationRequest request) {
        String email = resendVerificationValidator.validate(request);

        User user = userRepository.findByEmailForUpdate(email)
                .orElse(null);

        if (user == null || user.getEmailVerifiedAt() != null) {
            return;
        }

        Instant now = Instant.now();

        boolean inCooldown = tokenRepository
                .findFirstByUserIdOrderByCreatedAtDesc(user.getId())
                .map(token -> token.getCreatedAt()
                        .plus(RESEND_COOLDOWN)
                        .isAfter(now))
                .orElse(false);

        if (inCooldown) {
            return;
        }

        String rawToken = issueToken(user.getId());

        eventPublisher.publishEvent(
                new EmailVerificationRequested(
                        user.getEmail(),
                        rawToken
                )
        );
    }



}
