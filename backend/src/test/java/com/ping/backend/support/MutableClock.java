
package com.ping.backend.support;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public final class MutableClock extends Clock {

    private final AtomicReference<Instant> currentTime;

    private final ZoneId zone;

    public MutableClock(Instant initialTime, ZoneId zone) {
        this(
                new AtomicReference<>(
                        Objects.requireNonNull(
                                initialTime,
                                "initialTime is required"
                        )
                ),
                zone
        );
    }

    private MutableClock(
            AtomicReference<Instant> currentTime,
            ZoneId zone
    ) {
        this.currentTime = currentTime;

        this.zone = Objects.requireNonNull(
                zone,
                "zone is required"
        );
    }

    @Override
    public ZoneId getZone() {
        return zone;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        return new MutableClock(currentTime, zone);
    }

    @Override
    public Instant instant() {
        return currentTime.get();
    }

    public void setInstant(Instant instant) {
        currentTime.set(
                Objects.requireNonNull(
                        instant,
                        "instant is required"
                )
        );
    }

    public void advance(Duration duration) {
        Objects.requireNonNull(
                duration,
                "duration is required"
        );

        currentTime.updateAndGet(
                instant -> instant.plus(duration)
        );
    }
}
