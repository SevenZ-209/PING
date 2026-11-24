
package com.ping.backend.validation;

import org.springframework.stereotype.Component;

import java.util.Locale;
import java.util.regex.Pattern;

@Component
public class EmailValidator {

    private static final int MAX_EMAIL_LENGTH = 255;

    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    public String validate(String rawEmail) {
        if (rawEmail == null || rawEmail.isBlank()) {
            throw new IllegalArgumentException(
                    "Email is required"
            );
        }

        String email = rawEmail.trim().toLowerCase(Locale.ROOT);

        if (email.length() > MAX_EMAIL_LENGTH) {
            throw new IllegalArgumentException(
                    "Email must not exceed 255 characters"
            );
        }

        if (!EMAIL_PATTERN.matcher(email).matches()) {
            throw new IllegalArgumentException(
                    "Invalid email format"
            );
        }

        return email;
    }
}
