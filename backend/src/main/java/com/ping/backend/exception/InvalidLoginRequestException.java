package com.ping.backend.exception;

public class InvalidLoginRequestException extends RuntimeException {

    public InvalidLoginRequestException(String message) {
        super(message);
    }
}