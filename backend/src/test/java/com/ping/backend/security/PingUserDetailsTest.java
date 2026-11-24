package com.ping.backend.security;

import com.ping.backend.entity.User;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class PingUserDetailsTest {

    private final UUID userId = UUID.randomUUID();
    private final String email = "test@example.com";
    private final String passwordHash = "test-password-hash";

    private User createUser(boolean emailVerified) {
        Instant now = Instant.now();

        return new User(
                userId,
                email,
                passwordHash,
                "Test User",
                now,
                now,
                emailVerified ? now : null
        );
    }

    @Test
    void getId_returnsUserId() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.getId()).isEqualTo(userId);
    }

    @Test
    void getUsername_returnsEmail() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.getUsername()).isEqualTo(email);
    }

    @Test
    void getPassword_returnsPasswordHash() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.getPassword()).isEqualTo(passwordHash);
    }

    @Test
    void verifiedEmail_returnsTrue() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.isEmailVerified()).isTrue();
    }

    @Test
    void unverifiedEmail_returnsFalse() {
        PingUserDetails details = new PingUserDetails(createUser(false));

        assertThat(details.isEmailVerified()).isFalse();
        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void getAuthorities_returnsEmptyCollection() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.getAuthorities()).isEmpty();
    }

    @Test
    void accountStatus_isEnabledAndUnrestricted() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();
    }

    @Test
    void eraseCredentials_clearsPasswordHash() {
        PingUserDetails details = new PingUserDetails(createUser(true));

        details.eraseCredentials();

        assertThat(details.getPassword()).isNull();
        assertThat(details.getId()).isEqualTo(userId);
        assertThat(details.getUsername()).isEqualTo(email);
        assertThat(details.isEmailVerified()).isTrue();
    }

    @Test
    void eraseCredentials_doesNotModifyUserEntity() {
        User user = createUser(true);
        PingUserDetails details = new PingUserDetails(user);

        details.eraseCredentials();

        assertThat(details.getPassword()).isNull();
        assertThat(user.getPasswordHash()).isEqualTo(passwordHash);
    }
}