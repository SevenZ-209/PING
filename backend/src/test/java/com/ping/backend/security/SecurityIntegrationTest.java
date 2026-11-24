
package com.ping.backend.security;

import com.ping.backend.config.SecurityConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.http.HttpHeaders;
import static org.hamcrest.Matchers.matchesPattern;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(
        controllers = SecurityIntegrationTest.TestController.class
)
@Import({
        SecurityConfig.class,
        RestAuthenticationEntryPoint.class,
        RestAccessDeniedHandler.class,
        SecurityIntegrationTest.TestController.class
})
class SecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private JwtDecoder jwtDecoder;

    @RestController
    public static class TestController {

        @GetMapping("/api/v1/test/protected")
        public Map<String, String> protectedEndpoint() {
            return Map.of("message", "Access granted");
        }
        @GetMapping("/api/v1/test/forbidden")
        public void forbiddenEndpoint() {
            throw new AccessDeniedException("Access denied");
        }

        @PostMapping({
                "/api/v1/auth/register",
                "/api/v1/auth/verify-email",
                "/api/v1/auth/resend-verification",
                "/api/v1/auth/login",
                "/api/v1/auth/refresh",
                "/api/v1/auth/logout"
        })
        public Map<String, String> publicEndpoint() {
            return Map.of("message", "Public access granted");
        }
    }

    @Test
    void protectedEndpoint_unauthenticated_returns401()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/protected"))
                .andExpect(status().isUnauthorized());
    }
    @Test
    void publicEndpoints_withoutAuthentication_areAccessible()
            throws Exception {

        String[] endpoints = {
                "/api/v1/auth/register",
                "/api/v1/auth/verify-email",
                "/api/v1/auth/resend-verification",
                "/api/v1/auth/login",
                "/api/v1/auth/refresh",
                "/api/v1/auth/logout"
        };

        for (String endpoint : endpoints) {
            mockMvc.perform(post(endpoint))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message")
                            .value("Public access granted"));
        }
    }

    @Test
    void protectedEndpoint_unauthenticated_returnsErrorResponse()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/protected"))
                .andExpect(status().isUnauthorized())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(jsonPath("$.message")
                        .value("Authentication is required"));
    }
    @Test
    void publicEndpoint_wrongHttpMethod_requiresAuthentication()
            throws Exception {

        mockMvc.perform(get("/api/v1/auth/register"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }
    @Test
    void protectedEndpoint_authenticated_returns200()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/protected")
                        .with(user("test-user")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message")
                        .value("Access granted"));
    }

    @Test
    void unauthenticatedRequest_doesNotCreateSession()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/protected"))
                .andExpect(status().isUnauthorized())
                .andExpect(result -> assertThat(
                        result.getRequest().getSession(false)
                ).isNull());
    }

    @Test
    void authenticatedRequest_doesNotCreateSession()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/protected")
                        .with(user("test-user")))
                .andExpect(status().isOk())
                .andExpect(result -> assertThat(
                        result.getRequest().getSession(false)
                ).isNull());
    }

    @Test
    void httpBasicAuthentication_isRejected() throws Exception {
        mockMvc.perform(get("/api/v1/test/protected")
                        .with(httpBasic("test-user", "password123")))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(header().string(
                        HttpHeaders.WWW_AUTHENTICATE,
                        matchesPattern("^Bearer(?:\\s+.*)?$")
                ));
    }

    @Test
    void defaultLoginPage_isNotAvailable()
            throws Exception {

        mockMvc.perform(get("/login"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
                .andExpect(header().doesNotExist("Location"));
    }

    @Test
    void authenticatedRequest_accessDenied_returns403()
            throws Exception {

        mockMvc.perform(get("/api/v1/test/forbidden")
                        .with(user("test-user")))
                .andExpect(status().isForbidden())
                .andExpect(content()
                        .contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("ACCESS_DENIED"))
                .andExpect(jsonPath("$.message").value("Access denied"));
    }

}
