
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.dto.auth.RefreshTokenRotationOutcome;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenRotationTransactionService {

    private final AuthSessionRepository authSessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final AuthProperties authProperties;
    private final Clock clock;

    public RefreshTokenRotationTransactionService(
            AuthSessionRepository authSessionRepository,
            RefreshTokenRepository refreshTokenRepository,
            RefreshTokenGenerator refreshTokenGenerator,
            AuthProperties authProperties,
            Clock clock
    ) {
        this.authSessionRepository = authSessionRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.authProperties = authProperties;
        this.clock = clock;
    }

    @Transactional(
            propagation = Propagation.REQUIRED,
            isolation = Isolation.READ_COMMITTED
    )
    public RefreshTokenRotationOutcome rotate(String tokenHash) {
        Objects.requireNonNull(tokenHash, "tokenHash is required");

        Optional<UUID> sessionId =
                refreshTokenRepository.findSessionIdByTokenHash(tokenHash);

        if (sessionId.isEmpty()) {
            return RefreshTokenRotationOutcome.rejected();
        }

        Optional<AuthSession> lockedSession =
                authSessionRepository.findByIdForUpdate(sessionId.get());

        if (lockedSession.isEmpty()) {
            return RefreshTokenRotationOutcome.rejected();
        }

        AuthSession session = lockedSession.get();

        Optional<RefreshToken> storedToken =
                refreshTokenRepository.findByTokenHash(tokenHash);

        if (storedToken.isEmpty()) {
            return RefreshTokenRotationOutcome.rejected();
        }

        RefreshToken currentToken = storedToken.get();

        if (!currentToken.getSessionId().equals(session.getId())) {
            return RefreshTokenRotationOutcome.rejected();
        }

        Instant now = clock.instant()
                .truncatedTo(ChronoUnit.MICROS);

        if (!session.isActive(now)) {
            return RefreshTokenRotationOutcome.rejected();
        }

        if (currentToken.isConsumed()) {
            session.revoke(now);

            return RefreshTokenRotationOutcome.reuseDetected();
        }

        if (currentToken.isExpired(now)) {
            return RefreshTokenRotationOutcome.rejected();
        }

        Instant sessionExpiresAt = session.getExpiresAt();

        Instant refreshTokenExpiresAt = now.plus(
                authProperties.refreshTokenTtl()
        );

        if (refreshTokenExpiresAt.isAfter(sessionExpiresAt)) {
            refreshTokenExpiresAt = sessionExpiresAt;
        }

        String rawRefreshToken = refreshTokenGenerator.generate();

        String replacementTokenHash =
                refreshTokenGenerator.hash(rawRefreshToken);

        RefreshToken replacementToken = new RefreshToken(
                UUID.randomUUID(),
                session.getId(),
                replacementTokenHash,
                now,
                refreshTokenExpiresAt
        );

        currentToken.consume(now);

        refreshTokenRepository.flush();

        refreshTokenRepository.saveAndFlush(replacementToken);

        return RefreshTokenRotationOutcome.success(
                new RefreshTokenRotationResult(
                        session.getUserId(),
                        session.getId(),
                        rawRefreshToken,
                        refreshTokenExpiresAt,
                        sessionExpiresAt
                )
        );
    }
}
