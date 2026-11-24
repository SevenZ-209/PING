package com.ping.backend.config;

import com.ping.backend.config.properties.JwtProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;

import javax.crypto.SecretKey;
import java.time.Duration;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwtPropertiesTest {

    private final String secret = Base64.getEncoder()
            .encodeToString(new byte[32]);

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withInitializer(context -> {
                        context.getEnvironment()
                                .getPropertySources()
                                .remove("systemEnvironment");

                        context.getEnvironment()
                                .getPropertySources()
                                .remove("systemProperties");
                    })
                    .withUserConfiguration(JwtConfig.class);

    private ApplicationContextRunner validContextRunner() {
        return contextRunner.withPropertyValues(
                "jwt.secret=" + secret,
                "jwt.issuer=ping-backend",
                "jwt.audience=ping-api",
                "jwt.access-token-ttl=15m"
        );
    }

    @Test
    void validConfiguration_contextStartsSuccessfully() {
        validContextRunner().run(context -> {
            assertThat(context).hasNotFailed();

            assertThat(context)
                    .hasSingleBean(JwtProperties.class)
                    .hasSingleBean(SecretKey.class)
                    .hasSingleBean(JwtEncoder.class)
                    .hasSingleBean(JwtDecoder.class);

            JwtProperties properties =
                    context.getBean(JwtProperties.class);

            assertThat(properties.secret()).isEqualTo(secret);
            assertThat(properties.issuer()).isEqualTo("ping-backend");
            assertThat(properties.audience()).isEqualTo("ping-api");
            assertThat(properties.accessTokenTtl())
                    .isEqualTo(Duration.ofMinutes(15));
        });
    }

    @Test
    void missingSecret_contextFails() {
        contextRunner.withPropertyValues(
                "jwt.issuer=ping-backend",
                "jwt.audience=ping-api",
                "jwt.access-token-ttl=15m"
        ).run(context -> {
            assertThat(context).hasFailed();
        });
    }

    @Test
    void blankSecret_contextFails() {
        validContextRunner()
                .withPropertyValues("jwt.secret=")
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

    @Test
    void missingIssuer_contextFails() {
        contextRunner.withPropertyValues(
                "jwt.secret=" + secret,
                "jwt.audience=ping-api",
                "jwt.access-token-ttl=15m"
        ).run(context -> {
            assertThat(context).hasFailed();
        });
    }

    @Test
    void missingAudience_contextFails() {
        contextRunner.withPropertyValues(
                "jwt.secret=" + secret,
                "jwt.issuer=ping-backend",
                "jwt.access-token-ttl=15m"
        ).run(context -> {
            assertThat(context).hasFailed();
        });
    }

    @Test
    void missingTtl_contextFails() {
        contextRunner.withPropertyValues(
                "jwt.secret=" + secret,
                "jwt.issuer=ping-backend",
                "jwt.audience=ping-api"
        ).run(context -> {
            assertThat(context).hasFailed();
        });
    }

    @Test
    void invalidTtlFormat_contextFails() {
        validContextRunner()
                .withPropertyValues("jwt.access-token-ttl=invalid")
                .run(context -> {
                    assertThat(context).hasFailed();
                });
    }

    @Test
    void invalidBase64Secret_contextFails() {
        validContextRunner()
                .withPropertyValues("jwt.secret=invalid-base64!!!")
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseMessage(
                                    "JWT secret must be valid Base64"
                            );
                });
    }

    @Test
    void invalidSecretLength_contextFails() {
        String invalidSecret = Base64.getEncoder()
                .encodeToString(new byte[31]);

        validContextRunner()
                .withPropertyValues("jwt.secret=" + invalidSecret)
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseMessage(
                                    "JWT secret must contain exactly 32 bytes"
                            );
                });
    }

    @Test
    void zeroTtl_contextFails() {
        validContextRunner()
                .withPropertyValues("jwt.access-token-ttl=0s")
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseMessage(
                                    "JWT access token TTL must be positive"
                            );
                });
    }
}