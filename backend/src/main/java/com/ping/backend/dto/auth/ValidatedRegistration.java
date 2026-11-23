
package com.ping.backend.auth;

public record ValidatedRegistration(
        String email,
        String password,
        String displayName
) {
}
