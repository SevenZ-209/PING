package com.ping.backend.repository;

import com.ping.backend.entity.AuthSession;

import java.util.Optional;
import java.util.UUID;

public interface AuthSessionQueries {

    Optional<AuthSession> findByIdForUpdate(UUID sessionId);
}