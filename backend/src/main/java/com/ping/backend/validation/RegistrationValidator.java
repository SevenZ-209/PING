package com.ping.backend.validation;
import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.dto.auth.ValidatedRegistration;
import com.ping.backend.exception.InvalidRegistrationException;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;

@Component
public class RegistrationValidator {

    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_BYTES = 72;
    private static final int MAX_DISPLAY_NAME_LENGTH = 100;
    private final EmailValidator emailValidator;

    public RegistrationValidator(EmailValidator emailValidator) {
        this.emailValidator = emailValidator;
    }


    public ValidatedRegistration validate(RegisterRequest request) {
        if (request == null) {
            throw new InvalidRegistrationException(
                    "Registration request is required"
            );
        }

        String email = validateEmail(request.email());
        String password = validatePassword(request.password());
        String displayName = validateDisplayName(request.displayName());

        return new ValidatedRegistration(
                email,
                password,
                displayName
        );
    }

    private String validateEmail(String rawEmail) {
        try {
            return emailValidator.validate(rawEmail);
        } catch (IllegalArgumentException exception) {
            throw new InvalidRegistrationException(
                    exception.getMessage()
            );
        }
    }

    private String validatePassword(String password) {
        if (password == null || password.isBlank()) {
            throw new InvalidRegistrationException(
                    "Password is required"
            );
        }

        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new InvalidRegistrationException(
                    "Password must contain at least 8 characters"
            );
        }

        if (password.getBytes(StandardCharsets.UTF_8).length
                > MAX_PASSWORD_BYTES) {
            throw new InvalidRegistrationException(
                    "Password must not exceed 72 UTF-8 bytes"
            );
        }

        return password;
    }

    private String validateDisplayName(String rawDisplayName) {
        if (rawDisplayName == null || rawDisplayName.isBlank()) {
            throw new InvalidRegistrationException(
                    "Display name is required"
            );
        }

        String displayName = rawDisplayName.trim();

        if (displayName.length() > MAX_DISPLAY_NAME_LENGTH) {
            throw new InvalidRegistrationException(
                    "Display name must not exceed 100 characters"
            );
        }

        return displayName;
    }
}
