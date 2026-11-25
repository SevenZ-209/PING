package com.ping.backend.entity;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenTest {

    private static final UUID TOKEN_ID = UUID.randomUUID();
    private static final UUID SESSION_ID = UUID.randomUUID();

    private static final String TOKEN_HASH =
            "0123456789abcdef".repeat(4);

    private static final Instant CREATED_AT =
            Instant.parse("2025-01-01T00:00:00Z");

    private static final Instant EXPIRES_AT =
            CREATED_AT.plus(30, ChronoUnit.DAYS);

    private RefreshToken token;

    @BeforeEach
    void setUp() {
        token = new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                EXPIRES_AT
        );
    }

    private void assertInvalidTokenHash(String tokenHash) {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                tokenHash,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "tokenHash must contain 64 lowercase hexadecimal characters"
                );
    }

    @Test
    void constructor_validData_createsToken() {
        assertThat(token.getId()).isEqualTo(TOKEN_ID);
        assertThat(token.getSessionId()).isEqualTo(SESSION_ID);
        assertThat(token.getTokenHash()).isEqualTo(TOKEN_HASH);
        assertThat(token.getCreatedAt()).isEqualTo(CREATED_AT);
        assertThat(token.getExpiresAt()).isEqualTo(EXPIRES_AT);
        assertThat(token.getConsumedAt()).isNull();
    }

    @Test
    void constructor_nullId_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                null,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("id is required");
    }

    @Test
    void constructor_nullSessionId_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                null,
                TOKEN_HASH,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("sessionId is required");
    }

    @Test
    void constructor_nullTokenHash_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                null,
                CREATED_AT,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("tokenHash is required");
    }

    @Test
    void constructor_nullCreatedAt_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                null,
                EXPIRES_AT
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("createdAt is required");
    }

    @Test
    void constructor_nullExpiresAt_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                null
        ))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("expiresAt is required");
    }

    @Test
    void constructor_expirationEqualsCreation_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                CREATED_AT
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expiresAt must be after createdAt");
    }

    @Test
    void constructor_expirationBeforeCreation_rejects() {
        assertThatThrownBy(() -> new RefreshToken(
                TOKEN_ID,
                SESSION_ID,
                TOKEN_HASH,
                CREATED_AT,
                CREATED_AT.minusSeconds(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("expiresAt must be after createdAt");
    }

    @Test
    void constructor_emptyHash_rejects() {
        assertInvalidTokenHash("");
    }

    @Test
    void constructor_blankHash_rejects() {
        assertInvalidTokenHash(" ".repeat(64));
    }

    @Test
    void constructor_shortHash_rejects() {
        assertInvalidTokenHash("a".repeat(63));
    }

    @Test
    void constructor_longHash_rejects() {
        assertInvalidTokenHash("a".repeat(65));
    }

    @Test
    void constructor_uppercaseHash_rejects() {
        assertInvalidTokenHash("A".repeat(64));
    }

    @Test
    void constructor_nonHexadecimalHash_rejects() {
        assertInvalidTokenHash("a".repeat(63) + "g");
    }

    @Test
    void constructor_rawRefreshToken_rejects() {
        assertInvalidTokenHash("A".repeat(43));
    }

    @Test
    void isExpired_beforeExpiration_returnsFalse() {
        assertThat(token.isExpired(
                EXPIRES_AT.minusNanos(1)
        )).isFalse();
    }

    @Test
    void isExpired_atExpiration_returnsTrue() {
        assertThat(token.isExpired(EXPIRES_AT)).isTrue();
    }

    @Test
    void isExpired_afterExpiration_returnsTrue() {
        assertThat(token.isExpired(
                EXPIRES_AT.plusNanos(1)
        )).isTrue();
    }

    @Test
    void isExpired_nullTime_rejects() {
        assertThatThrownBy(() -> token.isExpired(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("now is required");
    }

    @Test
    void isConsumed_newToken_returnsFalse() {
        assertThat(token.isConsumed()).isFalse();
    }

    @Test
    void consume_validTime_consumesToken() {
        Instant consumedAt = CREATED_AT.plusSeconds(60);

        token.consume(consumedAt);

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.getConsumedAt()).isEqualTo(consumedAt);
    }

    @Test
    void consume_atCreation_succeeds() {
        token.consume(CREATED_AT);

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.getConsumedAt()).isEqualTo(CREATED_AT);
    }

    @Test
    void consume_immediatelyBeforeExpiration_succeeds() {
        Instant consumedAt = EXPIRES_AT.minusNanos(1);

        token.consume(consumedAt);

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.getConsumedAt()).isEqualTo(consumedAt);
    }

    @Test
    void consume_atExpiration_rejects() {
        assertThatThrownBy(() -> token.consume(EXPIRES_AT))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Refresh token is not valid");

        assertThat(token.isConsumed()).isFalse();
        assertThat(token.getConsumedAt()).isNull();
    }

    @Test
    void consume_afterExpiration_rejects() {
        assertThatThrownBy(() -> token.consume(
                EXPIRES_AT.plusNanos(1)
        ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Refresh token is not valid");

        assertThat(token.isConsumed()).isFalse();
        assertThat(token.getConsumedAt()).isNull();
    }

    @Test
    void consume_beforeCreation_rejects() {
        assertThatThrownBy(() -> token.consume(
                CREATED_AT.minusNanos(1)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "consumedAt must not be before createdAt"
                );

        assertThat(token.isConsumed()).isFalse();
        assertThat(token.getConsumedAt()).isNull();
    }

    @Test
    void consume_alreadyConsumed_rejects() {
        Instant firstConsumedAt = CREATED_AT.plusSeconds(60);

        token.consume(firstConsumedAt);

        assertThatThrownBy(() -> token.consume(
                CREATED_AT.plusSeconds(120)
        ))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Refresh token is not valid");

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.getConsumedAt())
                .isEqualTo(firstConsumedAt);
    }

    @Test
    void consume_nullTime_rejects() {
        assertThatThrownBy(() -> token.consume(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("now is required");

        assertThat(token.isConsumed()).isFalse();
        assertThat(token.getConsumedAt()).isNull();
    }

    @Test
    void isExpired_consumedTokenAfterExpiration_returnsTrue() {
        Instant consumedAt = CREATED_AT.plusSeconds(60);

        token.consume(consumedAt);

        assertThat(token.isConsumed()).isTrue();
        assertThat(token.isExpired(EXPIRES_AT)).isTrue();
        assertThat(token.getConsumedAt()).isEqualTo(consumedAt);
    }
}