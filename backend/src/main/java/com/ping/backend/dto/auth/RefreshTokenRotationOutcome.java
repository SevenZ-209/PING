
package com.ping.backend.dto.auth;

import java.util.Objects;

public record RefreshTokenRotationOutcome(
        Status status,
        RefreshTokenRotationResult result
) {

    public enum Status {
        SUCCESS,
        REJECTED,
        REUSE_DETECTED
    }

    public RefreshTokenRotationOutcome {
        Objects.requireNonNull(status, "status is required");

        if (status == Status.SUCCESS && result == null) {
            throw new IllegalArgumentException(
                    "Successful rotation requires a result"
            );
        }

        if (status != Status.SUCCESS && result != null) {
            throw new IllegalArgumentException(
                    "Rejected rotation must not contain a result"
            );
        }
    }

    public static RefreshTokenRotationOutcome success(
            RefreshTokenRotationResult result
    ) {
        return new RefreshTokenRotationOutcome(
                Status.SUCCESS,
                result
        );
    }

    public static RefreshTokenRotationOutcome rejected() {
        return new RefreshTokenRotationOutcome(
                Status.REJECTED,
                null
        );
    }

    public static RefreshTokenRotationOutcome reuseDetected() {
        return new RefreshTokenRotationOutcome(
                Status.REUSE_DETECTED,
                null
        );
    }

    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }
}
