package com.ping.backend.security;

import com.ping.backend.entity.User;
import com.ping.backend.repository.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class PingUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private PingUserDetailsService userDetailsService;

    private final UUID userId = UUID.randomUUID();
    private final String email = "test@example.com";
    private final String passwordHash = "test-password-hash";

    private User createUser(String hash, boolean emailVerified) {
        Instant now = Instant.now();

        return new User(
                userId,
                email,
                hash,
                "Test User",
                now,
                now,
                emailVerified ? now : null
        );
    }

    @Test
    void verifiedUser_returnsUserDetails() {
        User user = createUser(passwordHash, true);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(user));

        var result = userDetailsService.loadUserByUsername(email);

        assertThat(result).isInstanceOf(PingUserDetails.class);

        PingUserDetails details = (PingUserDetails) result;

        assertThat(details.getId()).isEqualTo(userId);
        assertThat(details.getUsername()).isEqualTo(email);
        assertThat(details.getPassword()).isEqualTo(passwordHash);
        assertThat(details.isEmailVerified()).isTrue();
    }

    @Test
    void unverifiedUser_returnsUserDetails() {
        User user = createUser(passwordHash, false);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(user));

        PingUserDetails details = (PingUserDetails)
                userDetailsService.loadUserByUsername(email);

        assertThat(details.isEmailVerified()).isFalse();
        assertThat(details.isEnabled()).isTrue();
    }

    @Test
    void nonexistentUser_throwsException() {
        when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                userDetailsService.loadUserByUsername(email)
        )
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("User not found");
    }

    @Test
    void nullPasswordHash_throwsException() {
        User user = createUser(null, true);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(user));

        assertThatThrownBy(() ->
                userDetailsService.loadUserByUsername(email)
        )
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("User not found");
    }

    @Test
    void blankPasswordHash_throwsException() {
        User user = createUser("   ", true);

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(user));

        assertThatThrownBy(() ->
                userDetailsService.loadUserByUsername(email)
        )
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("User not found");
    }

    @Test
    void loadUserByUsername_queriesRepositoryWithCorrectEmail() {
        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(
                        createUser(passwordHash, true)
                ));

        userDetailsService.loadUserByUsername(email);

        verify(userRepository, times(1)).findByEmail(email);
        verifyNoMoreInteractions(userRepository);
    }


}