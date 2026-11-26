
package com.ping.backend.service;

import com.ping.backend.config.properties.AuthProperties;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import com.ping.backend.repository.AuthSessionRepository;
import com.ping.backend.repository.RefreshTokenRepository;
import com.ping.backend.security.RefreshTokenGenerator;
import org.springframework.stereotype.Service;
import com.ping.backend.entity.AuthSession;
import com.ping.backend.entity.RefreshToken;
import org.springframework.transaction.annotation.Transactional;


import java.time.Clock;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;


@Service
public class RefreshTokenIssuanceService {

    private final AuthSessionRepository authSessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final AuthProperties authProperties;
    private final Clock clock;

    public RefreshTokenIssuanceService(
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




    @Transactional
    public RefreshTokenIssuanceResult issue(UUID userId) {
        Objects.requireNonNull(userId, "userId is required");

        Instant now = clock.instant()
                .truncatedTo(ChronoUnit.MICROS);

        Instant sessionExpiresAt = now.plus(
                authProperties.sessionTtl()
        );

        Instant refreshTokenExpiresAt = now.plus(
                authProperties.refreshTokenTtl()
        );

        if (refreshTokenExpiresAt.isAfter(sessionExpiresAt)) {
            refreshTokenExpiresAt = sessionExpiresAt;
        }

        String rawRefreshToken = refreshTokenGenerator.generate();

        String tokenHash = refreshTokenGenerator.hash(rawRefreshToken);

        AuthSession session = new AuthSession(
                UUID.randomUUID(),
                userId,
                now,
                sessionExpiresAt
        );

        RefreshToken refreshToken = new RefreshToken(
                UUID.randomUUID(),
                session.getId(),
                tokenHash,
                now,
                refreshTokenExpiresAt
        );

        authSessionRepository.saveAndFlush(session);

        refreshTokenRepository.saveAndFlush(refreshToken);

        return new RefreshTokenIssuanceResult(
                rawRefreshToken,
                session.getId(),
                refreshTokenExpiresAt,
                sessionExpiresAt
        );
    }

}
