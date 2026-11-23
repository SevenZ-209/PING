package com.ping.backend.exception;

import com.ping.backend.dto.ApiErrorResponse;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(InvalidRegistrationException.class)
    public ResponseEntity<ApiErrorResponse> handleInvalidRegistration(
            InvalidRegistrationException exception
    ) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ApiErrorResponse(
                        "INVALID_REGISTRATION",
                        exception.getMessage()
                ));
    }

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<ApiErrorResponse> handleEmailAlreadyExists(
            EmailAlreadyExistsException exception
    ) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(new ApiErrorResponse(
                        "EMAIL_ALREADY_EXISTS",
                        "Email is already registered"
                ));
    }
}