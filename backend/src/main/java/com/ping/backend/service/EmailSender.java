
package com.ping.backend.service;

public interface EmailSender {

    void sendVerificationEmail(
            String recipientEmail,
            String verificationToken
    );
}
