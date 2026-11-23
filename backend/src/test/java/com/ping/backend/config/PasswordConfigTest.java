
package com.ping.backend.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

class PasswordConfigTest {

    private final PasswordEncoder passwordEncoder =
            new PasswordConfig().passwordEncoder();

    @Test
    void passwordEncoder_shouldHashAndVerifyPassword() {
        String rawPassword = "MySecurePassword123!";

        String hash = passwordEncoder.encode(rawPassword);

        assertThat(hash).isNotEqualTo(rawPassword);
        assertThat(passwordEncoder.matches(rawPassword, hash))
                .isTrue();
        assertThat(passwordEncoder.matches("WrongPassword", hash))
                .isFalse();
    }
}
