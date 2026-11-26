package com.ping.backend.service;

import com.ping.backend.dto.auth.AccessToken;
import com.ping.backend.dto.auth.LoginRequest;
import com.ping.backend.dto.auth.LoginResponse;
import com.ping.backend.entity.User;
import com.ping.backend.exception.EmailNotVerifiedException;
import com.ping.backend.exception.InvalidCredentialsException;
import com.ping.backend.exception.InvalidLoginRequestException;
import com.ping.backend.security.PingUserDetails;
import com.ping.backend.validation.EmailValidator;
import com.ping.backend.validation.LoginValidator;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.JwtEncodingException;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtTokenService jwtTokenService;

    @Mock
    private RefreshTokenIssuanceService refreshTokenIssuanceService;

    private final LoginValidator loginValidator =
            new LoginValidator(new EmailValidator());

    private final UUID userId = UUID.randomUUID();

    private final String email = "user@example.com";
    private final String password = "password123";
    private final String token = "test-access-token";
    private final String rawRefreshToken = "A".repeat(43);

    private final UUID sessionId = UUID.randomUUID();

    private final Instant refreshTokenExpiresAt =
            Instant.parse("2026-12-01T00:00:00Z");

    private final Instant sessionExpiresAt =
            Instant.parse("2027-01-30T00:00:00Z");

    private final RefreshTokenIssuanceResult issuanceResult =
            new RefreshTokenIssuanceResult(
                    rawRefreshToken,
                    sessionId,
                    refreshTokenExpiresAt,
                    sessionExpiresAt
            );

    private LoginService loginService;

    @BeforeEach
    void setUp() {
        loginService = new LoginService(
                loginValidator,
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    private PingUserDetails createUserDetails(boolean verified) {
        Instant now = Instant.now();

        User user = new User(
                userId,
                email,
                "test-password-hash",
                "Test User",
                now,
                now,
                verified ? now : null
        );

        PingUserDetails userDetails = new PingUserDetails(user);
        userDetails.eraseCredentials();

        return userDetails;
    }

    private Authentication createAuthentication(boolean verified) {
        PingUserDetails userDetails = createUserDetails(verified);

        return UsernamePasswordAuthenticationToken.authenticated(
                userDetails,
                null,
                userDetails.getAuthorities()
        );
    }

    private LoginRequest createLoginRequest() {
        return new LoginRequest(email, password);
    }


    private void mockSuccessfulLogin() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(createAuthentication(true));

        when(jwtTokenService.generateAccessToken(userId))
                .thenReturn(new AccessToken(token, 900L));

        when(refreshTokenIssuanceService.issue(userId))
                .thenReturn(issuanceResult);
    }



    @Test
    void login_withValidCredentials_returnsLoginResponse() {
        mockSuccessfulLogin();

        LoginResponse response =
                loginService.login(createLoginRequest());

        assertThat(response.accessToken())
                .isEqualTo(token);

        assertThat(response.tokenType())
                .isEqualTo("Bearer");

        assertThat(response.expiresIn())
                .isEqualTo(900L);

        assertThat(response.refreshToken())
                .isEqualTo(rawRefreshToken);

        assertThat(response.refreshTokenExpiresAt())
                .isEqualTo(refreshTokenExpiresAt);

        assertThat(response.sessionExpiresAt())
                .isEqualTo(sessionExpiresAt);

        verify(authenticationManager)
                .authenticate(any(Authentication.class));

        verify(jwtTokenService)
                .generateAccessToken(userId);

        verify(refreshTokenIssuanceService)
                .issue(userId);
    }

    @Test
    void login_normalizesEmailBeforeAuthentication() {
        mockSuccessfulLogin();

        LoginRequest request = new LoginRequest(
                "  User@Example.com  ",
                password
        );

        loginService.login(request);

        ArgumentCaptor<Authentication> captor =
                ArgumentCaptor.forClass(Authentication.class);

        verify(authenticationManager)
                .authenticate(captor.capture());

        assertThat(captor.getValue().getPrincipal())
                .isEqualTo(email);

        assertThat(captor.getValue().isAuthenticated())
                .isFalse();
    }

    @Test
    void login_preservesOriginalPassword() {
        mockSuccessfulLogin();

        String rawPassword = "  password123  ";

        loginService.login(
                new LoginRequest(email, rawPassword)
        );

        ArgumentCaptor<Authentication> captor =
                ArgumentCaptor.forClass(Authentication.class);

        verify(authenticationManager)
                .authenticate(captor.capture());

        assertThat(captor.getValue().getCredentials())
                .isEqualTo(rawPassword);
    }
    @Test
    void login_withInvalidEmail_throwsInvalidLoginRequestException() {
        LoginRequest request = new LoginRequest(
                "invalid-email",
                password
        );

        assertThatThrownBy(() -> loginService.login(request))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Invalid email format");

        verifyNoInteractions(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    @Test
    void login_withMissingPassword_throwsInvalidLoginRequestException() {
        LoginRequest request = new LoginRequest(email, null);

        assertThatThrownBy(() -> loginService.login(request))
                .isInstanceOf(InvalidLoginRequestException.class)
                .hasMessage("Password is required");

        verifyNoInteractions(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    @Test
    void login_withIncorrectCredentials_throwsInvalidCredentialsException() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        )
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid email or password");

        verifyNoInteractions(
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    @Test
    void login_whenUserNotFound_throwsInvalidCredentialsException() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(new UsernameNotFoundException("User not found"));

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        )
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid email or password");

        verifyNoInteractions(
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }
    @Test
    void login_whenEmailNotVerified_throwsEmailNotVerifiedException() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(createAuthentication(false));

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        )
                .isInstanceOf(EmailNotVerifiedException.class)
                .hasMessage("Email address has not been verified");

        verify(authenticationManager)
                .authenticate(any(Authentication.class));

        verifyNoInteractions(
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    @Test
    void login_withUnexpectedPrincipal_throwsIllegalStateException() {
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated(
                        email,
                        null,
                        List.of()
                );

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(authentication);

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        )
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Unexpected authentication principal");

        verifyNoInteractions(
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }
    @Test
    void login_whenAuthenticationSystemFails_propagatesException() {
        InternalAuthenticationServiceException exception =
                new InternalAuthenticationServiceException(
                        "Database unavailable"
                );

        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenThrow(exception);

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        ).isSameAs(exception);

        verifyNoInteractions(
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

    @Test
    void login_whenTokenGenerationFails_propagatesException() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(createAuthentication(true));

        JwtEncodingException exception =
                new JwtEncodingException("Token signing failed");

        when(jwtTokenService.generateAccessToken(userId))
                .thenThrow(exception);

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        ).isSameAs(exception);

        verify(jwtTokenService)
                .generateAccessToken(userId);

        verifyNoInteractions(refreshTokenIssuanceService);
    }



    @Test
    void loginResponseToString_doesNotExposeCredentials() {
        mockSuccessfulLogin();

        LoginResponse response =
                loginService.login(createLoginRequest());

        assertThat(response.toString())
                .doesNotContain(token)
                .doesNotContain(rawRefreshToken)
                .contains("accessToken=REDACTED")
                .contains("refreshToken=REDACTED")
                .contains("tokenType=Bearer")
                .contains("expiresIn=900")
                .contains("refreshTokenExpiresAt=" + refreshTokenExpiresAt)
                .contains("sessionExpiresAt=" + sessionExpiresAt);
    }



    @Test
    void login_authenticatesBeforeIssuingTokens() {
        mockSuccessfulLogin();

        loginService.login(createLoginRequest());

        InOrder inOrder = inOrder(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );

        inOrder.verify(authenticationManager)
                .authenticate(any(Authentication.class));

        inOrder.verify(jwtTokenService)
                .generateAccessToken(userId);

        inOrder.verify(refreshTokenIssuanceService)
                .issue(userId);

        verifyNoMoreInteractions(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }


    @Test
    void login_whenRefreshTokenIssuanceFails_propagatesException() {
        when(authenticationManager.authenticate(any(Authentication.class)))
                .thenReturn(createAuthentication(true));

        when(jwtTokenService.generateAccessToken(userId))
                .thenReturn(new AccessToken(token, 900L));

        IllegalStateException exception =
                new IllegalStateException("Refresh token issuance failed");

        when(refreshTokenIssuanceService.issue(userId))
                .thenThrow(exception);

        assertThatThrownBy(() ->
                loginService.login(createLoginRequest())
        ).isSameAs(exception);

        InOrder inOrder = inOrder(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );

        inOrder.verify(authenticationManager)
                .authenticate(any(Authentication.class));

        inOrder.verify(jwtTokenService)
                .generateAccessToken(userId);

        inOrder.verify(refreshTokenIssuanceService)
                .issue(userId);

        verifyNoMoreInteractions(
                authenticationManager,
                jwtTokenService,
                refreshTokenIssuanceService
        );
    }

}