
package com.ping.backend.dto;

import jakarta.validation.constraints.NotBlank;

public record VerifyEmailRequest(
        @NotBlank String token
) {
}
