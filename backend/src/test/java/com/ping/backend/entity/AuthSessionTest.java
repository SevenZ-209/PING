package com.ping.backend.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthSessionTest {

    private static final UUID SESSION_ID = UUID.randomUUID();
    private static final UUID USER_ID = UUID.randomUUID();

    private static final Instant CREATED_AT =
            Instant.parse("2025-01-01T00:00:00Z");

    private static final Instant EXPIRES_AT =
            CREATED_AT.plus(90, ChronoUnit.DAYS);

    private AuthSession session;

    @BeforeEach
    void setUp() {
        session = new AuthSession(
                SESSION_ID,
                USER_ID,
                CREATED_AT,
                EXPIRES_AT
        );
    }

    @Test
    void constructor_validData_createsSession() {
        assertThat(session.getId()).isEqualTo(SESSION_ID);
        assertThat(session.getUserId()).isEqualTo(USER_ID);
        assertThat(session.getCreatedAt()).isEqualTo(CREATED_AT);
        assertThat(session.getExpiresAt()).isEqualTo(EXPIRES_AT);
        assertThat(session.getRevokedAt()).isNull();
    }

    @Test
    void constructor_nullId_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                null,
                USER_ID,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("id is required");
    }

    @Test
    void constructor_nullUserId_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                SESSION_ID,
                null,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("userId is required");
    }

    @Test
    void constructor_nullCreatedAt_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                SESSION_ID,
                USER_ID,
                null,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("createdAt is required");
    }

    @Test
    void constructor_nullExpiresAt_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                SESSION_ID,
                USER_ID,
                CREATED_AT,
                null
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expiresAt is required");
    }

    @Test
    void constructor_expirationEqualsCreation_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                SESSION_ID,
                USER_ID,
                CREATED_AT,
                CREATED_AT
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expiresAt must be after createdAt");
    }

    @Test
    void constructor_expirationBeforeCreation_rejects() {
        assertThatThrownBy(() -> new AuthSession(
                SESSION_ID,
                USER_ID,
                CREATED_AT,
                CREATED_AT.minusSeconds(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expiresAt must be after createdAt");
    }

    @Test
    void isExpired_beforeExpiration_returnsFalse() {
        assertThat(session.isExpired(
                EXPIRES_AT.minusNanos(1)
        )).isFalse();
    }

    @Test
    void isExpired_atExpiration_returnsTrue() {
        assertThat(session.isExpired(EXPIRES_AT)).isTrue();
    }

    @Test
    void isExpired_afterExpiration_returnsTrue() {
        assertThat(session.isExpired(
                EXPIRES_AT.plusNanos(1)
        )).isTrue();
    }

    @Test
    void isExpired_nullTime_rejects() {
        assertThatThrownBy(() -> session.isExpired(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("now is required");
    }

    @Test
    void isRevoked_newSession_returnsFalse() {
        assertThat(session.isRevoked()).isFalse();
    }

    @Test
    void isActive_validSession_returnsTrue() {
        assertThat(session.isActive(CREATED_AT)).isTrue();
    }

    @Test
    void isActive_expiredSession_returnsFalse() {
        assertThat(session.isActive(EXPIRES_AT)).isFalse();
    }

    @Test
    void isActive_revokedSession_returnsFalse() {
        Instant now = CREATED_AT.plusSeconds(60);

        session.revoke(now);

        assertThat(session.isActive(now)).isFalse();
    }

    @Test
    void revoke_validTime_revokesSession() {
        Instant revokedAt = CREATED_AT.plusSeconds(60);

        session.revoke(revokedAt);

        assertThat(session.isRevoked()).isTrue();
        assertThat(session.getRevokedAt()).isEqualTo(revokedAt);
    }

    @Test
    void revoke_alreadyRevoked_preservesOriginalTimestamp() {
        Instant firstRevokedAt = CREATED_AT.plusSeconds(60);
        Instant secondRevokedAt = CREATED_AT.plusSeconds(120);

        session.revoke(firstRevokedAt);
        session.revoke(secondRevokedAt);

        assertThat(session.isRevoked()).isTrue();
        assertThat(session.getRevokedAt())
                .isEqualTo(firstRevokedAt);
    }

    @Test
    void revoke_beforeCreation_rejects() {
        assertThatThrownBy(() -> session.revoke(
                CREATED_AT.minusSeconds(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("revokedAt must not be before createdAt");

        assertThat(session.isRevoked()).isFalse();
        assertThat(session.getRevokedAt()).isNull();
    }

    @Test
    void revoke_atCreation_succeeds() {
        session.revoke(CREATED_AT);

        assertThat(session.isRevoked()).isTrue();
        assertThat(session.getRevokedAt()).isEqualTo(CREATED_AT);
    }

    @Test
    void revoke_afterExpiration_succeeds() {
        Instant revokedAt = EXPIRES_AT.plusSeconds(1);

        session.revoke(revokedAt);

        assertThat(session.isRevoked()).isTrue();
        assertThat(session.isExpired(revokedAt)).isTrue();
        assertThat(session.getRevokedAt()).isEqualTo(revokedAt);
    }

    @Test
    void revoke_nullTime_rejects() {
        assertThatThrownBy(() -> session.revoke(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("now is required");

        assertThat(session.getRevokedAt()).isNull();
    }

    @Test
    void revoke_alreadyRevokedWithInvalidTime_rejects() {
        Instant revokedAt = CREATED_AT.plusSeconds(60);

        session.revoke(revokedAt);

        assertThatThrownBy(() -> session.revoke(
                CREATED_AT.minusSeconds(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("revokedAt must not be before createdAt");

        assertThat(session.getRevokedAt()).isEqualTo(revokedAt);
    }
}