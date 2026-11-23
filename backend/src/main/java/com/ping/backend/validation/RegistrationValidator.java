package com.ping.backend.validation;
import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.dto.auth.ValidatedRegistration;
import com.ping.backend.exception.InvalidRegistrationException;

import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;

@Component
public class RegistrationValidator {

    private static final int MAX_EMAIL_LENGTH = 255;
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final int MAX_PASSWORD_BYTES = 72;
    private static final int MAX_DISPLAY_NAME_LENGTH = 100;

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

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
        if (rawEmail == null || rawEmail.isBlank()) {
            throw new InvalidRegistrationException(
                    "Email is required"
            );
        }

        String email = rawEmail.trim().toLowerCase(Locale.ROOT);

        if (email.length() > MAX_EMAIL_LENGTH) {
            throw new InvalidRegistrationException(
                    "Email must not exceed 255 characters"
            );
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new InvalidRegistrationException(
                    "Invalid email format"
            );
        }

        return email;
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
