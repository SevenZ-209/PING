
package com.ping.backend.dto.auth;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenRotationOutcomeTest {

    private final String rawToken = "A".repeat(43);

    private final RefreshTokenRotationResult result =
            new RefreshTokenRotationResult(
                    UUID.randomUUID(),
                    UUID.randomUUID(),
                    rawToken,
                    Instant.parse("2026-12-01T00:00:00Z"),
                    Instant.parse("2027-01-30T00:00:00Z")
            );

    @Test
    void success_containsRotationResult() {
        RefreshTokenRotationOutcome outcome =
                RefreshTokenRotationOutcome.success(result);

        assertThat(outcome.status())
                .isEqualTo(
                        RefreshTokenRotationOutcome.Status.SUCCESS
                );

        assertThat(outcome.result()).isSameAs(result);
        assertThat(outcome.isSuccess()).isTrue();
    }

    @Test
    void rejected_doesNotContainResult() {
        RefreshTokenRotationOutcome outcome =
                RefreshTokenRotationOutcome.rejected();

        assertThat(outcome.status())
                .isEqualTo(
                        RefreshTokenRotationOutcome.Status.REJECTED
                );

        assertThat(outcome.result()).isNull();
        assertThat(outcome.isSuccess()).isFalse();
    }

    @Test
    void reuseDetected_doesNotContainResult() {
        RefreshTokenRotationOutcome outcome =
                RefreshTokenRotationOutcome.reuseDetected();

        assertThat(outcome.status())
                .isEqualTo(
                        RefreshTokenRotationOutcome.Status.REUSE_DETECTED
                );

        assertThat(outcome.result()).isNull();
        assertThat(outcome.isSuccess()).isFalse();
    }

    @Test
    void constructor_whenSuccessHasNoResult_throwsException() {
        assertThatThrownBy(() ->
                new RefreshTokenRotationOutcome(
                        RefreshTokenRotationOutcome.Status.SUCCESS,
                        null
                )
        )
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "Successful rotation requires a result"
                );
    }

    @ParameterizedTest
    @EnumSource(
            value = RefreshTokenRotationOutcome.Status.class,
            names = {"REJECTED", "REUSE_DETECTED"}
    )
    void constructor_whenFailureContainsResult_throwsException(
            RefreshTokenRotationOutcome.Status status
    ) {
        assertThatThrownBy(() ->
                new RefreshTokenRotationOutcome(status, result)
        )
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(
                        "Rejected rotation must not contain a result"
                );
    }

    @Test
    void constructor_whenStatusIsNull_throwsException() {
        assertThatThrownBy(() ->
                new RefreshTokenRotationOutcome(null, null)
        )
                .isInstanceOf(NullPointerException.class)
                .hasMessage("status is required");
    }

    @Test
    void toString_doesNotExposeRawRefreshToken() {
        RefreshTokenRotationOutcome outcome =
                RefreshTokenRotationOutcome.success(result);

        assertThat(outcome.toString())
                .doesNotContain(rawToken)
                .contains("status=SUCCESS")
                .contains("rawRefreshToken=REDACTED");
    }
}
