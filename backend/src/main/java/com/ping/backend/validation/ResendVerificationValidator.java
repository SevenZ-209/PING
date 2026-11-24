
package com.ping.backend.validation;

import com.ping.backend.dto.auth.ResendVerificationRequest;
import com.ping.backend.exception.InvalidResendVerificationException;
import org.springframework.stereotype.Component;

@Component
public class ResendVerificationValidator {

    private final EmailValidator emailValidator;

    public ResendVerificationValidator(EmailValidator emailValidator) {
        this.emailValidator = emailValidator;
    }

    public String validate(ResendVerificationRequest request) {
        if (request == null) {
            throw new InvalidResendVerificationException(
                    "Resend verification request is required"
            );
        }

        try {
            return emailValidator.validate(request.email());
        } catch (IllegalArgumentException exception) {
            throw new InvalidResendVerificationException(
                    exception.getMessage()
            );
        }
    }
}
