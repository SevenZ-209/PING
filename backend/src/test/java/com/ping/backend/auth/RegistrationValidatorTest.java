
package com.ping.backend.auth;
import com.ping.backend.validation.RegistrationValidator;
import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.dto.auth.ValidatedRegistration;
import com.ping.backend.exception.InvalidRegistrationException;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RegistrationValidatorTest {

    private final RegistrationValidator validator =
            new RegistrationValidator();

    @Test
    void validRequest_shouldNormalizeEmailAndDisplayName() {
        RegisterRequest request = new RegisterRequest(
                "  Leon@Example.com  ",
                "password123",
                "  Leon Dinh  "
        );

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.email()).isEqualTo("leon@example.com");
        assertThat(result.password()).isEqualTo("password123");
        assertThat(result.displayName()).isEqualTo("Leon Dinh");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void invalidEmail_shouldBeRejected(String email) {
        RegisterRequest request =
                new RegisterRequest(email, "password123", "Leon");

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
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
        RegisterRequest request =
                new RegisterRequest(email, "password123", "Leon");

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Invalid email format");
    }

    @Test
    void emailLongerThan255Characters_shouldBeRejected() {
        String email = "a".repeat(244) + "@example.com";

        RegisterRequest request =
                new RegisterRequest(email, "password123", "Leon");

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Email must not exceed 255 characters");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void blankPassword_shouldBeRejected(String password) {
        RegisterRequest request =
                new RegisterRequest("leon@example.com", password, "Leon");

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password is required");
    }

    @Test
    void passwordShorterThan8Characters_shouldBeRejected() {
        RegisterRequest request =
                new RegisterRequest("leon@example.com", "1234567", "Leon");

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password must contain at least 8 characters");
    }

    @Test
    void passwordWithExactly8Characters_shouldBeAccepted() {
        RegisterRequest request =
                new RegisterRequest("leon@example.com", "12345678", "Leon");

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.password()).isEqualTo("12345678");
    }

    @Test
    void passwordLongerThan72Bytes_shouldBeRejected() {
        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                "a".repeat(73),
                "Leon"
        );

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password must not exceed 72 UTF-8 bytes");
    }

    @Test
    void passwordShouldNotBeTrimmed() {
        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                "  password123  ",
                "Leon"
        );

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.password()).isEqualTo("  password123  ");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"   ", "\t"})
    void blankDisplayName_shouldBeRejected(String displayName) {
        RegisterRequest request =
                new RegisterRequest(
                        "leon@example.com",
                        "password123",
                        displayName
                );

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Display name is required");
    }

    @Test
    void displayNameLongerThan100Characters_shouldBeRejected() {
        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                "password123",
                "a".repeat(101)
        );

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Display name must not exceed 100 characters");
    }

    @Test
    void nullRequest_shouldBeRejected() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Registration request is required");
    }

    @Test
    void emailWithExactly255Characters_shouldBeAccepted() {
        String email = "a".repeat(243) + "@example.com";

        RegisterRequest request =
                new RegisterRequest(email, "password123", "Leon");

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.email()).isEqualTo(email);
    }

    @Test
    void displayNameWithExactly100Characters_shouldBeAccepted() {
        String displayName = "a".repeat(100);

        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                "password123",
                displayName
        );

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.displayName()).isEqualTo(displayName);
    }

    @Test
    void passwordWithExactly72Bytes_shouldBeAccepted() {
        String password = "a".repeat(72);

        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                password,
                "Leon"
        );

        ValidatedRegistration result = validator.validate(request);

        assertThat(result.password()).isEqualTo(password);
    }

    @Test
    void unicodePasswordOver72Bytes_shouldBeRejected() {
        String password = "😀".repeat(19);

        RegisterRequest request = new RegisterRequest(
                "leon@example.com",
                password,
                "Leon"
        );

        assertThatThrownBy(() -> validator.validate(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password must not exceed 72 UTF-8 bytes");
    }

}
