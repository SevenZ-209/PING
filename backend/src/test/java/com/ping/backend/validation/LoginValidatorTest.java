package com.ping.backend.validation;

import com.ping.backend.dto.auth.LoginRequest;
import com.ping.backend.dto.auth.ValidatedLogin;
import com.ping.backend.exception.InvalidLoginRequestException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LoginValidatorTest {

    private final LoginValidator validator =
            new LoginValidator(new EmailValidator());

    @Test
    void validRequest_returnsValidatedLogin() {
        LoginRequest request = new LoginRequest(
                "test@example.com",
                "password123"
        );

        ValidatedLogin result = validator.validate(request);

        assertThat(result.email()).isEqualTo("test@example.com");
        assertThat(result.password()).isEqualTo("password123");
    }

    @Test
    void email_isNormalized() {
        LoginRequest request = new LoginRequest(
                " Test@Example.COM ",
                "password123"
        );

        ValidatedLogin result = validator.validate(request);

        assertThat(result.email()).isEqualTo("test@example.com");
    }

    @Test
    void password_isPreserved() {
        String password = " Password123 ";

        ValidatedLogin result = validator.validate(
                new LoginRequest("test@example.com", password)
        );

        assertThat(result.password()).isEqualTo(password);
    }

    @Test
    void nullRequest_isRejected() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Login request is required");
    }

    @Test
    void nullEmail_isRejected() {
        assertThatThrownBy(() -> validator.validate(
                new LoginRequest(null, "password123")
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Email is required");
    }

    @Test
    void blankEmail_isRejected() {
        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("   ", "password123")
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Email is required");
    }

    @Test
    void invalidEmailFormat_isRejected() {
        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("invalid-email", "password123")
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Invalid email format");
    }

    @Test
    void emailExceedsMaximumLength_isRejected() {
        String email = "a".repeat(244) + "@example.com";

        assertThatThrownBy(() -> validator.validate(
                new LoginRequest(email, "password123")
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Email must not exceed 255 characters");
    }

    @Test
    void nullPassword_isRejected() {
        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("test@example.com", null)
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Password is required");
    }

    @Test
    void blankPassword_isRejected() {
        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("test@example.com", "   ")
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Password is required");
    }

    @Test
    void shortPassword_isAccepted() {
        ValidatedLogin result = validator.validate(
                new LoginRequest("test@example.com", "abc")
        );

        assertThat(result.password()).isEqualTo("abc");
    }

    @Test
    void passwordExactly72Bytes_isAccepted() {
        String password = "a".repeat(72);

        ValidatedLogin result = validator.validate(
                new LoginRequest("test@example.com", password)
        );

        assertThat(result.password()).isEqualTo(password);
    }

    @Test
    void passwordExceeds72Bytes_isRejected() {
        String password = "a".repeat(73);

        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("test@example.com", password)
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Password must not exceed 72 bytes");
    }

    @Test
    void unicodePasswordExactly72Bytes_isAccepted() {
        String password = "\u4F60".repeat(24);

        ValidatedLogin result = validator.validate(
                new LoginRequest("test@example.com", password)
        );

        assertThat(result.password()).isEqualTo(password);
    }

    @Test
    void unicodePasswordExceeds72Bytes_isRejected() {
        String password = "\u4F60".repeat(25);

        assertThatThrownBy(() -> validator.validate(
                new LoginRequest("test@example.com", password)
        ))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Password must not exceed 72 bytes");
    }

}