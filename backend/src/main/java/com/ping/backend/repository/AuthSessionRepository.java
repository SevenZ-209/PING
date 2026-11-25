package com.ping.backend.repository;

import com.ping.backend.entity.AuthSession;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface AuthSessionRepository
        extends JpaRepository<AuthSession, UUID>,
        AuthSessionQueries {
}