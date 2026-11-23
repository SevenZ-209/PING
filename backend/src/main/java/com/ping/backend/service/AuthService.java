
package com.ping.backend.service;

import com.ping.backend.dto.auth.RegisterRequest;
import com.ping.backend.dto.auth.ValidatedRegistration;
import com.ping.backend.entity.User;
import com.ping.backend.exception.EmailAlreadyExistsException;
import com.ping.backend.repository.UserRepository;
import com.ping.backend.validation.RegistrationValidator;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RegistrationValidator registrationValidator;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RegistrationValidator registrationValidator
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.registrationValidator = registrationValidator;
    }

    public boolean isEmailRegistered(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    public String hashPassword(String rawPassword) {
        return passwordEncoder.encode(rawPassword);
    }

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
    }
}
