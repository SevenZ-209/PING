package com.ping.backend.exception;

public class InvalidResendVerificationException extends RuntimeException {

    public InvalidResendVerificationException(String message) {
        super(message);
    }
}
