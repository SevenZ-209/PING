
package com.ping.backend.service;

import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.dto.auth.ValidatedRegistration;
import com.ping.backend.entity.User;
import com.ping.backend.exception.EmailAlreadyExistsException;
import com.ping.backend.repository.UserRepository;
import com.ping.backend.validation.RegistrationValidator;
import com.ping.backend.service.EmailVerificationService;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.ping.backend.event.EmailVerificationRequested;
import org.springframework.context.ApplicationEventPublisher;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegistrationValidator registrationValidator;
    private final EmailVerificationService emailVerificationService;
    private final ApplicationEventPublisher eventPublisher;


    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RegistrationValidator registrationValidator,
            EmailVerificationService emailVerificationService,
            ApplicationEventPublisher eventPublisher
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.registrationValidator = registrationValidator;
        this.emailVerificationService = emailVerificationService;
        this.eventPublisher = eventPublisher;
    }


    public boolean isEmailRegistered(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    public String hashPassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

    @Transactional
    public void register(RegisterRequest request) {
        ValidatedRegistration data =
                registrationValidator.validate(request);

        if (userRepository.findByEmail(data.email()).isPresent()) {
            throw new EmailAlreadyExistsException();
        }

        String passwordHash =
                passwordEncoder.encode(data.password());

        Instant now = Instant.now();

        User newUser = new User(
                UUID.randomUUID(),
                data.email(),
                passwordHash,
                data.displayName(),
                now,
                now,
                null
        );

        try {
            userRepository.saveAndFlush(newUser);
        } catch (DataIntegrityViolationException exception) {
            throw new EmailAlreadyExistsException();
        }


        String rawToken = emailVerificationService.issueToken(newUser.getId());

        eventPublisher.publishEvent(
                new EmailVerificationRequested(
                        newUser.getEmail(),
                        rawToken
                )
        );

    }
}
