package com.ping.backend.security;

import com.ping.backend.config.AuthenticationConfig;
import com.ping.backend.config.PasswordConfig;
import com.ping.backend.entity.User;
import com.ping.backend.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationManagerTest {

    @Mock
    private UserRepository userRepository;

    private AuthenticationManager authenticationManager;
    private PasswordEncoder passwordEncoder;

    private final UUID userId = UUID.randomUUID();
    private final String email = "test@example.com";
    private final String password = "password123";

    @BeforeEach
    void setUp() {
        passwordEncoder = new PasswordConfig().passwordEncoder();

        PingUserDetailsService userDetailsService =
                new PingUserDetailsService(userRepository);

        authenticationManager = new AuthenticationConfig()
                .authenticationManager(
                        userDetailsService,
                        passwordEncoder
                );
    }

    private User createUser(String passwordHash, boolean emailVerified) {
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

    private void mockExistingUser(boolean emailVerified) {
        String passwordHash = passwordEncoder.encode(password);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(
                        createUser(passwordHash, emailVerified)
                ));
    }

    private Authentication authenticate(String email, String password) {
        return authenticationManager.authenticate(
                UsernamePasswordAuthenticationToken
                        .unauthenticated(email, password)
        );
    }

    @Test
    void correctCredentials_authenticatesUser() {
        mockExistingUser(true);

        Authentication result = authenticate(email, password);

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getPrincipal())
                .isInstanceOf(PingUserDetails.class);

        PingUserDetails principal =
                (PingUserDetails) result.getPrincipal();

        assertThat(principal.getId()).isEqualTo(userId);
        assertThat(principal.getUsername()).isEqualTo(email);
        assertThat(principal.isEmailVerified()).isTrue();
    }

    @Test
    void incorrectPassword_throwsBadCredentialsException() {
        mockExistingUser(true);

        assertThatThrownBy(() ->
                authenticate(email, "wrong-password")
        ).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void nonexistentUser_throwsBadCredentialsException() {
        when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                authenticate(email, password)
        ).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void unverifiedUserWithCorrectPassword_authenticatesUser() {
        mockExistingUser(false);

        Authentication result = authenticate(email, password);

        assertThat(result.isAuthenticated()).isTrue();

        PingUserDetails principal =
                (PingUserDetails) result.getPrincipal();

        assertThat(principal.isEmailVerified()).isFalse();
    }

    @Test
    void unverifiedUserWithIncorrectPassword_throwsBadCredentialsException() {
        mockExistingUser(false);

        assertThatThrownBy(() ->
                authenticate(email, "wrong-password")
        ).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void nullPasswordHash_throwsBadCredentialsException() {
        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(
                        createUser(null, true)
                ));

        assertThatThrownBy(() ->
                authenticate(email, password)
        ).isInstanceOf(BadCredentialsException.class);
    }

    @Test
    void blankPasswordHash_throwsBadCredentialsException() {
        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(
                        createUser("   ", true)
                ));

        assertThatThrownBy(() ->
                authenticate(email, password)
        ).isInstanceOf(BadCredentialsException.class);
    }
    @Test
    void successfulAuthentication_erasesCredentials() {
        mockExistingUser(true);

        Authentication result = authenticate(email, password);

        PingUserDetails principal =
                (PingUserDetails) result.getPrincipal();

        assertThat(result.isAuthenticated()).isTrue();
        assertThat(result.getCredentials()).isNull();
        assertThat(principal.getPassword()).isNull();
        assertThat(principal.getId()).isEqualTo(userId);
        assertThat(principal.getUsername()).isEqualTo(email);
        assertThat(principal.isEmailVerified()).isTrue();
    }
}