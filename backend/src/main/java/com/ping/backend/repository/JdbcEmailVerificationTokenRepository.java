package com.ping.backend.repository;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;

@Repository
public class JdbcEmailVerificationTokenRepository
        implements EmailVerificationTokenRepository {

    private final JdbcClient jdbcClient;

    public JdbcEmailVerificationTokenRepository(JdbcClient jdbcClient) {
        this.jdbcClient = jdbcClient;
    }

    @Override
    public void lockUser(UUID userId) {
        Integer found = jdbcClient.sql("""
                SELECT 1
                FROM users
                WHERE id = :userId
                FOR UPDATE
                """)
                .param("userId", userId)
                .query(Integer.class)
                .optional()
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));
    }

    @Override
    public void invalidateActiveTokens(UUID userId, Instant now) {
        jdbcClient.sql("""
                UPDATE email_verification_tokens
                SET invalidated_at = :now
                WHERE user_id = :userId
                  AND consumed_at IS NULL
                  AND invalidated_at IS NULL
                """)
                .param("userId", userId)
                .param("now", now.atOffset(ZoneOffset.UTC))
                .update();
    }

    @Override
    public void save(
            UUID id,
            UUID userId,
            String tokenHash,
            Instant createdAt,
            Instant expiresAt
    ) {
        jdbcClient.sql("""
                INSERT INTO email_verification_tokens
                    (id, user_id, token_hash, created_at, expires_at)
                VALUES
                    (:id, :userId, :tokenHash, :createdAt, :expiresAt)
                """)
                .param("id", id)
                .param("userId", userId)
                .param("tokenHash", tokenHash)
                .param("createdAt", createdAt.atOffset(ZoneOffset.UTC))
                .param("expiresAt", expiresAt.atOffset(ZoneOffset.UTC))
                .update();
    }
}
