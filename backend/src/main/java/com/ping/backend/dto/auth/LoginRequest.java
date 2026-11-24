package com.ping.backend.dto.auth;

public record LoginRequest(
        String email,
        String password
) {
}