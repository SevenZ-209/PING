package com.ping.backend.config;

import com.ping.backend.config.properties.AuthProperties;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.env.StandardEnvironment;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class AuthConfigTest {

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner()
                    .withInitializer(context -> {
                        context.getEnvironment()
                                .getPropertySources()
                                .remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);

                        context.getEnvironment()
                                .getPropertySources()
                                .remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
                    })
                    .withUserConfiguration(AuthConfig.class);

    @Test
    void authClock_validConfiguration_createsUtcClock() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=30d",
                        "auth.session-ttl=90d"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(Clock.class);

                    Clock clock = context.getBean(Clock.class);

                    assertThat(clock.getZone())
                            .isEqualTo(ZoneOffset.UTC);

                    assertThat(context.getBean(Clock.class))
                            .isSameAs(clock);
                });
    }

    @Test
    void authProperties_validConfiguration_bindsProperties() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=30d",
                        "auth.session-ttl=90d"
                )
                .run(context -> {
                    assertThat(context).hasNotFailed();

                    assertThat(context)
                            .hasSingleBean(AuthProperties.class);

                    AuthProperties properties =
                            context.getBean(AuthProperties.class);

                    assertThat(properties.refreshTokenTtl())
                            .isEqualTo(Duration.ofDays(30));

                    assertThat(properties.sessionTtl())
                            .isEqualTo(Duration.ofDays(90));
                });
    }

    @Test
    void authProperties_missingRefreshTokenTtl_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.session-ttl=90d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(
                                    IllegalArgumentException.class
                            )
                            .hasRootCauseMessage(
                                    "Refresh token TTL is required"
                            );
                });
    }

    @Test
    void authProperties_missingSessionTtl_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=30d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(
                                    IllegalArgumentException.class
                            )
                            .hasRootCauseMessage(
                                    "Session TTL is required"
                            );
                });
    }

    @Test
    void authProperties_invalidDurationFormat_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=invalid-duration",
                        "auth.session-ttl=90d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasStackTraceContaining(
                                    "auth.refresh-token-ttl"
                            )
                            .hasStackTraceContaining(
                                    "invalid-duration"
                            );
                });
    }

    @Test
    void authProperties_nonPositiveRefreshTokenTtl_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=0d",
                        "auth.session-ttl=90d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(
                                    IllegalArgumentException.class
                            )
                            .hasRootCauseMessage(
                                    "Refresh token TTL must be positive"
                            );
                });
    }

    @Test
    void authProperties_nonPositiveSessionTtl_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=30d",
                        "auth.session-ttl=-1d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(
                                    IllegalArgumentException.class
                            )
                            .hasRootCauseMessage(
                                    "Session TTL must be positive"
                            );
                });
    }

    @Test
    void authProperties_sessionTtlShorterThanRefreshTokenTtl_failsStartup() {
        contextRunner
                .withPropertyValues(
                        "auth.refresh-token-ttl=30d",
                        "auth.session-ttl=29d"
                )
                .run(context -> {
                    assertThat(context).hasFailed();

                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(
                                    IllegalArgumentException.class
                            )
                            .hasRootCauseMessage(
                                    "Session TTL must be greater than or equal to refresh token TTL"
                            );
                });
    }
}