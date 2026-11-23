
package com.ping.backend.auth;

public record RegisterRequest(
        String email,
        String password,
        String displayName
) {
}
