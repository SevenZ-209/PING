package com.ping.backend.dto.auth;

public record AccessToken(
        String token,
        long expiresIn
) {
    @Override
    public String toString() {
        return "AccessToken[token=REDACTED, expiresIn="
                + expiresIn + "]";
    }
}