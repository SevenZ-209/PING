package com.ping.backend.repository;

import com.ping.backend.entity.RefreshToken;

import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenQueries {

    Optional<UUID> findSessionIdByTokenHash(String tokenHash);

    Optional<RefreshToken> findByTokenHash(String tokenHash);
}