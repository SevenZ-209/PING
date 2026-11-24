package com.ping.backend.validation;

import com.ping.backend.dto.auth.LoginRequest;
import com.ping.backend.dto.auth.ValidatedLogin;
import com.ping.backend.exception.InvalidLoginRequestException;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class LoginValidator {

    private static final int MAX_PASSWORD_BYTES = 72;

    private final EmailValidator emailValidator;

    public LoginValidator(EmailValidator emailValidator) {
        this.emailValidator = emailValidator;
    }

    public ValidatedLogin validate(LoginRequest request) {
        if (request == null) {
            throw new InvalidLoginRequestException(
                    "Login request is required"
            );
        }

        String email = validateEmail(request.email());
        String password = validatePassword(request.password());

        return new ValidatedLogin(email, password);
    }

    private String validateEmail(String rawEmail) {
        try {
            return emailValidator.validate(rawEmail);
        } catch (IllegalArgumentException exception) {
            throw new InvalidLoginRequestException(
                    exception.getMessage()
            );
        }
    }

    private String validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new InvalidLoginRequestException(
                    "Password is required"
            );
        }

        if (password.getBytes(StandardCharsets.UTF_8).length
                > MAX_PASSWORD_BYTES) {
            throw new InvalidLoginRequestException(
                    "Password must not exceed 72 bytes"
            );
        }

        return password;
    }
}