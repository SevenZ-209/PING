
package com.ping.backend.dto.auth;

public record ValidatedRegistration(
        String email,
        String password,
        String displayName
) {
}
