package com.ping.backend.event;

public record EmailVerificationRequested(
        String recipientEmail,
        String verificationToken
) {
}
