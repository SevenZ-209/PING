package com.ping.backend.dto.auth;

public record LoginResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {
    @Override
    public String toString() {
        return "LoginResponse[accessToken=REDACTED, tokenType="
                + tokenType + ", expiresIn=" + expiresIn + "]";
    }
}