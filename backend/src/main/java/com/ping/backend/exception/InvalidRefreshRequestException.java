package com.ping.backend.exception;

public class InvalidRefreshRequestException extends RuntimeException {

    public InvalidRefreshRequestException() {
        super("Invalid refresh token format");
    }
}