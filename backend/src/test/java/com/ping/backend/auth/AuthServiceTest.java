
package com.ping.backend.auth;

import com.ping.backend.user.User;
import com.ping.backend.user.UserRepository;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import org.mockito.ArgumentCaptor;
import java.time.Instant;
import java.util.Optional;
import org.springframework.security.crypto.password.PasswordEncoder;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import org.junit.jupiter.api.BeforeEach;
import org.mockito.Mock;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DuplicateKeyException;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {


    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    private final RegistrationValidator registrationValidator =
            new RegistrationValidator();

    private AuthService authService;

    @BeforeEach
    void setUp() {
        authService = new AuthService(
                userRepository,
                passwordEncoder,
                registrationValidator
        );
    }


    @Test
    void isEmailRegistered_whenEmailDoesNotExist_returnsFalse() {
        String email = "new@example.com";

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

        boolean result = authService.isEmailRegistered(email);

        assertThat(result).isFalse();
        verify(userRepository).findByEmail(email);
    }

    @Test
    void isEmailRegistered_whenEmailExists_returnsTrue() {
        String email = "existing@example.com";
        Instant now = Instant.now();

        User existingUser = new User(
                UUID.randomUUID(),
                email,
                "test-hash",
                "Existing User",
                now,
                now,
                null
        );

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(existingUser));

        boolean result = authService.isEmailRegistered(email);

        assertThat(result).isTrue();
        verify(userRepository).findByEmail(email);
    }


    @Test
    void hashPassword_shouldUsePasswordEncoder() {
        String rawPassword = "MyPassword123!";
        String hashedPassword = "mocked-hash";

        when(passwordEncoder.encode(rawPassword))
                .thenReturn(hashedPassword);

        String result = authService.hashPassword(rawPassword);

        assertThat(result).isEqualTo(hashedPassword);
        verify(passwordEncoder).encode(rawPassword);
    }

    @Test
    void register_whenEmailAlreadyExists_throwsException() {
        String email = "existing@example.com";

        RegisterRequest request = new RegisterRequest(
                email,
                "MyPassword123!",
                "Test User"
        );

        User existingUser = new User(
                UUID.randomUUID(),
                email,
                "existing-hash",
                "Existing User",
                Instant.now(),
                Instant.now(),
                null
        );

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.of(existingUser));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(EmailAlreadyExistsException.class);

        verify(userRepository).findByEmail(email);
        verify(userRepository, never()).save(any(User.class));
        verifyNoInteractions(passwordEncoder);
    }

    @Test
    void register_whenEmailIsNew_hashesPasswordAndSavesUser() {
        String email = "new@example.com";
        String rawPassword = "MyPassword123!";
        String hashedPassword = "mocked-bcrypt-hash";

        RegisterRequest request = new RegisterRequest(
                email,
                rawPassword,
                "New User"
        );

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode(rawPassword))
                .thenReturn(hashedPassword);

        authService.register(request);

        ArgumentCaptor<User> userCaptor =
                ArgumentCaptor.forClass(User.class);

        verify(userRepository).save(userCaptor.capture());

        User savedUser = userCaptor.getValue();

        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo(email);
        assertThat(savedUser.getPasswordHash())
                .isEqualTo(hashedPassword);
        assertThat(savedUser.getDisplayName())
                .isEqualTo("New User");
        assertThat(savedUser.getEmailVerifiedAt()).isNull();

        verify(passwordEncoder).encode(rawPassword);
    }

    @Test
    void register_shouldNormalizeEmailBeforeCheckingAndSaving() {
        String rawEmail = "  Leon@Example.com  ";
        String normalizedEmail = "leon@example.com";

        RegisterRequest request = new RegisterRequest(
                rawEmail,
                "MyPassword123!",
                "Leon"
        );

        when(userRepository.findByEmail(normalizedEmail))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode("MyPassword123!"))
                .thenReturn("hashed-password");

        authService.register(request);

        verify(userRepository).findByEmail(normalizedEmail);

        ArgumentCaptor<User> userCaptor =
                ArgumentCaptor.forClass(User.class);

        verify(userRepository).save(userCaptor.capture());

        assertThat(userCaptor.getValue().getEmail())
                .isEqualTo(normalizedEmail);
    }

    @Test
    void register_whenEmailIsNull_throwsInvalidRegistrationException() {
        RegisterRequest request = new RegisterRequest(
                null,
                "MyPassword123!",
                "Test User"
        );

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Email is required");

        verifyNoInteractions(userRepository, passwordEncoder);
    }


    @Test
    void register_whenEmailIsBlank_throwsInvalidRegistrationException() {
        RegisterRequest request = new RegisterRequest(
                "   ",
                "MyPassword123!",
                "Test User"
        );

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Email is required");

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void register_whenEmailFormatIsInvalid_throwsInvalidRegistrationException() {
        RegisterRequest request = new RegisterRequest(
                "invalid-email",
                "MyPassword123!",
                "Test User"
        );

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Invalid email format");

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void register_whenPasswordIsNull_throwsInvalidRegistrationException() {
        RegisterRequest request = new RegisterRequest(
                "new@example.com",
                null,
                "Test User"
        );

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password is required");

        verifyNoInteractions(userRepository, passwordEncoder);
    }

    @Test
    void register_whenPasswordIsBlank_throwsInvalidRegistrationException() {
        RegisterRequest request = new RegisterRequest(
                "new@example.com",
                "   ",
                "Test User"
        );

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(InvalidRegistrationException.class)
                .hasMessage("Password is required");

        verifyNoInteractions(userRepository, passwordEncoder);
    }


    @Test
    void register_whenInsertHitsDuplicateKey_throwsEmailAlreadyExistsException() {
        String email = "race@example.com";

        RegisterRequest request = new RegisterRequest(
                email,
                "password123",
                "Test User"
        );

        when(userRepository.findByEmail(email))
                .thenReturn(Optional.empty());

        when(passwordEncoder.encode("password123"))
                .thenReturn("hashed-password");

        doThrow(new DuplicateKeyException("Duplicate email"))
                .when(userRepository)
                .save(any(User.class));

        assertThatThrownBy(() -> authService.register(request))
                .isInstanceOf(EmailAlreadyExistsException.class);

        verify(userRepository).findByEmail(email);
        verify(userRepository).save(any(User.class));
    }


}
