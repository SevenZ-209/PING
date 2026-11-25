package com.ping.backend.validation;

import com.ping.backend.exception.InvalidRefreshRequestException;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.regex.Pattern;

@Component
public class RefreshTokenValidator {

    private static final int TOKEN_LENGTH = 43;

    private static final int TOKEN_BYTES = 32;

    private static final Pattern TOKEN_PATTERN =
            Pattern.compile("[A-Za-z0-9_-]{43}");

    public String validate(String rawToken) {
        if (rawToken == null
                || rawToken.isBlank()
                || rawToken.length() != TOKEN_LENGTH
                || !TOKEN_PATTERN.matcher(rawToken).matches()) {
            throw new InvalidRefreshRequestException();
        }

        byte[] decodedBytes;

        try {
            decodedBytes = Base64.getUrlDecoder()
                    .decode(rawToken);
        } catch (IllegalArgumentException exception) {
            throw new InvalidRefreshRequestException();
        }

        if (decodedBytes.length != TOKEN_BYTES) {
            throw new InvalidRefreshRequestException();
        }

        String canonicalToken = Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(decodedBytes);

        if (!canonicalToken.equals(rawToken)) {
            throw new InvalidRefreshRequestException();
        }

        return rawToken;
    }
}