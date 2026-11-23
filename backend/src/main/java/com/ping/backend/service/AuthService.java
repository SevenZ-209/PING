
package com.ping.backend.auth;

import com.ping.backend.user.User;
import com.ping.backend.user.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.dao.DuplicateKeyException;
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
            userRepository.save(newUser);
        } catch (DuplicateKeyException exception) {
            throw new EmailAlreadyExistsException();
        }

    }
}
