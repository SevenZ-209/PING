package com.ping.backend.security;

import com.ping.backend.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.CredentialsContainer;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

public class PingUserDetails implements UserDetails, CredentialsContainer {
    private final UUID id;
    private final String email;
    private String passwordHash;
    private final boolean emailVerified;

    public PingUserDetails(User user) {
        this.id = user.getId();
        this.email = user.getEmail();
        this.passwordHash = user.getPasswordHash();
        this.emailVerified = user.getEmailVerifiedAt() != null;
    }

    public UUID getId() {
        return id;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public void eraseCredentials() {
        this.passwordHash = null;
    }
}