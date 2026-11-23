
package com.ping.backend.service;

import com.resend.Resend;
import com.resend.services.emails.model.CreateEmailOptions;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class ResendEmailSender implements EmailSender {

    private final Resend resend;
    private final String fromEmail;

    public ResendEmailSender(
            @Value("${resend.api-key}") String apiKey,
            @Value("${resend.from-email}") String fromEmail
    ) {
        this.resend = new Resend(apiKey);
        this.fromEmail = fromEmail;
    }

    @Override
    public void sendVerificationEmail(
            String recipientEmail,
            String verificationToken
    ) {
        String verificationLink =
                "http://localhost:8080/verify-email?token="
                        + verificationToken;

        CreateEmailOptions email = CreateEmailOptions.builder()
                .from(fromEmail)
                .to(recipientEmail)
                .subject("Verify your PING account")
                .html("""
                        <h2>Welcome to PING!</h2>
                        <p>Click the link below to verify your email:</p>
                        <a href="%s">Verify Email</a>
                        <p>This link expires in 24 hours.</p>
                        """.formatted(verificationLink))
                .build();

        try {
            resend.emails().send(email);
        } catch (Exception exception) {
            throw new IllegalStateException(
                    "Failed to send verification email",
                    exception
            );
        }
    }
}
