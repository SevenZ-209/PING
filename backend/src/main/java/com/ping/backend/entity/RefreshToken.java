package com.ping.backend.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

@Entity
@Table(name = "auth_refresh_tokens")
public class RefreshToken {

    private static final Pattern TOKEN_HASH_PATTERN =
            Pattern.compile("[0-9a-f]{64}");

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "session_id", nullable = false)
    private UUID sessionId;

    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "consumed_at")
    private Instant consumedAt;

    protected RefreshToken() {
    }

    public RefreshToken(
            UUID id,
            UUID sessionId,
            String tokenHash,
            Instant createdAt,
            Instant expiresAt
    ) {
        this.id = Objects.requireNonNull(id, "id is required");
        this.sessionId = Objects.requireNonNull(sessionId, "sessionId is required");
        this.tokenHash = Objects.requireNonNull(tokenHash, "tokenHash is required");
        this.createdAt = Objects.requireNonNull(createdAt, "createdAt is required");
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt is required");

        if (!TOKEN_HASH_PATTERN.matcher(tokenHash).matches()) {
            throw new IllegalArgumentException(
                    "tokenHash must contain 64 lowercase hexadecimal characters"
            );
        }

        if (!expiresAt.isAfter(createdAt)) {
            throw new IllegalArgumentException(
                    "expiresAt must be after createdAt"
            );
        }
    }

    public UUID getId() {
        return id;
    }

    public UUID getSessionId() {
        return sessionId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getConsumedAt() {
        return consumedAt;
    }

    public boolean isExpired(Instant now) {
        Objects.requireNonNull(now, "now is required");

        return !expiresAt.isAfter(now);
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public void consume(Instant now) {
        Objects.requireNonNull(now, "now is required");

        if (now.isBefore(createdAt)) {
            throw new IllegalArgumentException(
                    "consumedAt must not be before createdAt"
            );
        }

        if (isConsumed() || isExpired(now)) {
            throw new IllegalStateException(
                    "Refresh token is not valid"
            );
        }

        consumedAt = now;
    }
}