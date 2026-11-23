
package com.ping.backend.user;

import java.time.Instant;
import java.util.UUID;

public final class User {

    private final UUID id;
    private final String email;
    private final String passwordHash;
    private final String displayName;
    private final Instant createdAt;
    private final Instant updatedAt;
    private final Instant emailVerifiedAt;

    public User(
            UUID id,
            String email,
            String passwordHash,
            String displayName,
            Instant createdAt,
            Instant updatedAt,
            Instant emailVerifiedAt
    ) {
        this.id = id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.displayName = displayName;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.emailVerifiedAt = emailVerifiedAt;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getDisplayName() {
        return displayName;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public Instant getEmailVerifiedAt() {
        return emailVerifiedAt;
    }
}
