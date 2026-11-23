package com.ping.backend.controller;

import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.service.AuthService;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.ping.backend.dto.VerifyEmailRequest;
import jakarta.validation.Valid;
import java.util.Map;
import com.ping.backend.service.EmailVerificationService;


@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    private final AuthService authService;

    private final EmailVerificationService emailVerificationService;

    public AuthController(
            AuthService authService,
            EmailVerificationService emailVerificationService
    ) {
        this.authService = authService;
        this.emailVerificationService = emailVerificationService;
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(
            @RequestBody RegisterRequest request
    ) {
        authService.register(request);

        return ResponseEntity
                .status(HttpStatus.CREATED)
                .body(Map.of(
                        "message", "Registration successful"
                ));
    }


    @PostMapping("/verify-email")
    public ResponseEntity<Map<String, String>> verifyEmail(
            @Valid @RequestBody VerifyEmailRequest request
    ) {
        emailVerificationService.verifyToken(request.token());

        return ResponseEntity.ok(
                Map.of("message", "Email verified successfully")
        );
    }

}