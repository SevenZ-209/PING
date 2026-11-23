
package com.ping.backend.listener;

import com.ping.backend.event.EmailVerificationRequested;
import com.ping.backend.service.EmailSender;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

@Component
public class EmailVerificationListener {

    private static final Logger log =
            LoggerFactory.getLogger(EmailVerificationListener.class);

    private final EmailSender emailSender;

    public EmailVerificationListener(EmailSender emailSender) {
        this.emailSender = emailSender;
    }

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
    public void handle(EmailVerificationRequested event) {
        try {
            emailSender.sendVerificationEmail(
                    event.recipientEmail(),
                    event.verificationToken()
            );
        } catch (Exception exception) {
            log.error(
                    "Email verification delivery failed: {}",
                    exception.getClass().getSimpleName()
            );
        }
    }
}
