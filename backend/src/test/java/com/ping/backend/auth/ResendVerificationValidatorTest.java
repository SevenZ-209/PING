
package com.ping.backend.auth;

import com.ping.backend.dto.auth.ResendVerificationRequest;
import com.ping.backend.exception.InvalidResendVerificationException;
import com.ping.backend.validation.EmailValidator;
import com.ping.backend.validation.ResendVerificationValidator;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ResendVerificationValidatorTest {

    private final ResendVerificationValidator validator =
            new ResendVerificationValidator(new EmailValidator());

    @Test
    void validEmail_shouldBeAccepted() {
        var request = new ResendVerificationRequest(
                "user@example.com"
        );

        assertThat(validator.validate(request))
                .isEqualTo("user@example.com");
    }

    @Test
    void email_shouldBeNormalized() {
        var request = new ResendVerificationRequest(
                "  USER@EXAMPLE.COM  "
        );

        assertThat(validator.validate(request))
                .isEqualTo("user@example.com");
    }

    @Test
    void nullRequest_shouldBeRejected() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(InvalidResendVerificationException.class)
                .hasMessage("Resend verification request is required");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void blankEmail_shouldBeRejected(String email) {
        var request = new ResendVerificationRequest(email);

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidResendVerificationException.class)
                .hasMessage("Email is required");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "invalid-email",
            "abc@",
            "@example.com",
            "abc@example",
            "abc@@example.com"
    })
    void invalidEmailFormat_shouldBeRejected(String email) {
        var request = new ResendVerificationRequest(email);

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidResendVerificationException.class)
                .hasMessage("Invalid email format");
    }

    @Test
    void emailLongerThan255Characters_shouldBeRejected() {
        String email = "a".repeat(244) + "@example.com";
        var request = new ResendVerificationRequest(email);

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidResendVerificationException.class)
                .hasMessage("Email must not exceed 255 characters");
    }

    @Test
    void emailWithExactly255Characters_shouldBeAccepted() {
        String email = "a".repeat(243) + "@example.com";
        var request = new ResendVerificationRequest(email);

        assertThat(validator.validate(request))
                .isEqualTo(email);
    }
}
