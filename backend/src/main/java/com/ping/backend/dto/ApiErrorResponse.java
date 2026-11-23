package com.ping.backend.dto;

public record ApiErrorResponse(
        String code,
        String message
) {
}