package com.ping.backend.repository;

import com.ping.backend.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface RefreshTokenRepository
        extends JpaRepository<RefreshToken, UUID>,
        RefreshTokenQueries {
}