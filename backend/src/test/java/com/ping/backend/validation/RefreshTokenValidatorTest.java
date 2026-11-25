package com.ping.backend.validation;

import com.ping.backend.exception.InvalidRefreshRequestException;
import com.ping.backend.security.RefreshTokenGenerator;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshTokenValidatorTest {

    private final RefreshTokenValidator validator =
            new RefreshTokenValidator();

    private final RefreshTokenGenerator generator =
            new RefreshTokenGenerator();

    @Test
    void validate_validCanonicalToken_returnsToken() {
        String token = "A".repeat(43);

        assertThat(validator.validate(token))
                .isEqualTo(token);
    }

    @Test
    void validate_generatedToken_returnsToken() {
        String token = generator.generate();

        assertThat(validator.validate(token))
                .isEqualTo(token);
    }

    @Test
    void validate_validToken_returnsOriginalValue() {
        String token = "AbCdEf0123456789_-"
                + "A".repeat(25);

        String result = validator.validate(token);

        assertThat(result).isEqualTo(token);
        assertThat(result).isSameAs(token);
    }


    @Test
    void validate_nullToken_throwsException() {
        assertThatThrownBy(() -> validator.validate(null))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_emptyToken_throwsException() {
        assertThatThrownBy(() -> validator.validate(""))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_blankToken_throwsException() {
        String token = " ".repeat(43);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_shortToken_throwsException() {
        String token = "A".repeat(42);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_longToken_throwsException() {
        String token = "A".repeat(44);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }



    @Test
    void validate_paddedToken_throwsException() {
        String token = "A".repeat(43) + "=";

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_leadingWhitespace_throwsException() {
        String token = " " + "A".repeat(42);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_trailingWhitespace_throwsException() {
        String token = "A".repeat(42) + " ";

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_embeddedWhitespace_throwsException() {
        String token = "A".repeat(21)
                + " "
                + "A".repeat(21);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }


    @Test
    void validate_plusCharacter_throwsException() {
        String token = "A".repeat(21)
                + "+"
                + "A".repeat(21);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_slashCharacter_throwsException() {
        String token = "A".repeat(21)
                + "/"
                + "A".repeat(21);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_punctuationCharacter_throwsException() {
        String token = "A".repeat(21)
                + "!"
                + "A".repeat(21);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }

    @Test
    void validate_nonAsciiCharacter_throwsException() {
        String token = "A".repeat(21)
                + "\u00E9"
                + "A".repeat(21);

        assertThatThrownBy(() -> validator.validate(token))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }


    @Test
    void validate_nonCanonicalToken_throwsException() {
        String canonicalToken = "A".repeat(43);
        String nonCanonicalToken = "A".repeat(42) + "B";

        byte[] canonicalBytes = Base64.getUrlDecoder()
                .decode(canonicalToken);

        byte[] nonCanonicalBytes = Base64.getUrlDecoder()
                .decode(nonCanonicalToken);

        assertThat(nonCanonicalToken).hasSize(43);
        assertThat(nonCanonicalToken).matches("[A-Za-z0-9_-]{43}");
        assertThat(nonCanonicalBytes).hasSize(32);
        assertThat(nonCanonicalBytes).containsExactly(canonicalBytes);

        assertThatThrownBy(() -> validator.validate(nonCanonicalToken))
                .isInstanceOf(InvalidRefreshRequestException.class);
    }


    @Test
    void validate_invalidToken_throwsExceptionWithExpectedMessage() {
        assertThatThrownBy(() -> validator.validate("invalid-token"))
                .isInstanceOf(InvalidRefreshRequestException.class)
                .hasMessage("Invalid refresh token format");
    }


}
