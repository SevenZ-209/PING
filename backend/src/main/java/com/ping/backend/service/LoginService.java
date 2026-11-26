
package com.ping.backend.service;

import com.ping.backend.dto.auth.AccessToken;
import com.ping.backend.dto.auth.LoginRequest;
import com.ping.backend.dto.auth.LoginResponse;
import com.ping.backend.dto.auth.RefreshTokenIssuanceResult;
import com.ping.backend.dto.auth.ValidatedLogin;
import com.ping.backend.exception.EmailNotVerifiedException;
import com.ping.backend.exception.InvalidCredentialsException;
import com.ping.backend.security.PingUserDetails;
import com.ping.backend.validation.LoginValidator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class LoginService {

    private final LoginValidator loginValidator;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final RefreshTokenIssuanceService refreshTokenIssuanceService;

    public LoginService(
            LoginValidator loginValidator,
            AuthenticationManager authenticationManager,
            JwtTokenService jwtTokenService,
            RefreshTokenIssuanceService refreshTokenIssuanceService
    ) {
        this.loginValidator = loginValidator;
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.refreshTokenIssuanceService = refreshTokenIssuanceService;
    }

    public LoginResponse login(LoginRequest request) {
        ValidatedLogin data = loginValidator.validate(request);

        Authentication authentication;

        try {
            authentication = authenticationManager.authenticate(
                    UsernamePasswordAuthenticationToken.unauthenticated(
                            data.email(),
                            data.password()
                    )
            );
        } catch (BadCredentialsException | UsernameNotFoundException exception) {
            throw new InvalidCredentialsException();
        }

        if (!(authentication.getPrincipal() instanceof PingUserDetails userDetails)) {
            throw new IllegalStateException("Unexpected authentication principal");
        }

        if (!userDetails.isEmailVerified()) {
            throw new EmailNotVerifiedException();
        }

        AccessToken accessToken =
                jwtTokenService.generateAccessToken(userDetails.getId());

        RefreshTokenIssuanceResult refreshToken =
                refreshTokenIssuanceService.issue(userDetails.getId());

        return new LoginResponse(
                accessToken.token(),
                "Bearer",
                accessToken.expiresIn(),
                refreshToken.rawRefreshToken(),
                refreshToken.refreshTokenExpiresAt(),
                refreshToken.sessionExpiresAt()
        );
    }
}
