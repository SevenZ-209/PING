
package com.ping.backend.controller;

import com.ping.backend.repository.UserRepository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerIntegrationTest {

    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:17");

    static {
        postgres.start();
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Test
    void register_validRequest_returns201AndPersistsUser()
            throws Exception {

        String email = "api-" + UUID.randomUUID()
                + "@example.com";

        String requestBody = """
                {
                  "email": "%s",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.message")
                        .value("Registration successful"));

        var savedUser = userRepository.findByEmail(email);

        assertThat(savedUser).isPresent();
        assertThat(savedUser.orElseThrow().getDisplayName())
                .isEqualTo("Test User");
    }

    @Test
    void register_invalidEmail_returns400()
            throws Exception {

        String requestBody = """
                {
                  "email": "",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """;

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code")
                        .value("INVALID_REGISTRATION"));
    }

    @Test
    void register_duplicateEmail_returns409()
            throws Exception {

        String email = "duplicate-api-" + UUID.randomUUID()
                + "@example.com";

        String requestBody = """
                {
                  "email": "%s",
                  "password": "password123",
                  "displayName": "Test User"
                }
                """.formatted(email);

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isCreated());

        mockMvc.perform(post("/api/v1/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code")
                        .value("EMAIL_ALREADY_EXISTS"));
    }
}
