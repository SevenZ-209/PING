package com.ping.backend.service;

import com.ping.backend.config.properties.JwtProperties;
import com.ping.backend.dto.auth.AccessToken;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
public class JwtTokenService {

    private final JwtEncoder jwtEncoder;
    private final JwtProperties jwtProperties;

    public JwtTokenService(
            JwtEncoder jwtEncoder,
            JwtProperties jwtProperties
    ) {
        this.jwtEncoder = jwtEncoder;
        this.jwtProperties = jwtProperties;
    }

    public AccessToken generateAccessToken(UUID userId) {
        Objects.requireNonNull(userId, "User ID is required");

        Instant now = Instant.now()
                .truncatedTo(ChronoUnit.SECONDS);

        Instant expiresAt = now.plus(
                jwtProperties.accessTokenTtl()
        );

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject(userId.toString())
                .issuer(jwtProperties.issuer())
                .audience(List.of(jwtProperties.audience()))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .build();

        JwsHeader header = JwsHeader
                .with(MacAlgorithm.HS256)
                .build();

        Jwt jwt = jwtEncoder.encode(
                JwtEncoderParameters.from(header, claims)
        );

        return new AccessToken(
                jwt.getTokenValue(),
                jwtProperties.accessTokenTtl().toSeconds()
        );
    }
}
