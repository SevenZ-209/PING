package com.ping.backend.security;

import com.ping.backend.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class PingUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public PingUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String email) {
        return userRepository.findByEmail(email)
                .filter(user -> user.getPasswordHash() != null
                        && !user.getPasswordHash().isBlank())
                .map(PingUserDetails::new)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User not found")
                );
    }
}