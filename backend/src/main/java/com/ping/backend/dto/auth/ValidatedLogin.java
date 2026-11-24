package com.ping.backend.dto.auth;

public record ValidatedLogin(
        String email,
        String password
) {
}