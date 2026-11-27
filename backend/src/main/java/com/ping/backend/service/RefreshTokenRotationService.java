
package com.ping.backend.service;

import com.ping.backend.dto.auth.RefreshTokenRotationOutcome;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.exception.InvalidRefreshTokenException;
import com.ping.backend.security.RefreshTokenGenerator;
import com.ping.backend.validation.RefreshTokenValidator;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RefreshTokenRotationService {

    private final RefreshTokenValidator refreshTokenValidator;
    private final RefreshTokenGenerator refreshTokenGenerator;
    private final RefreshTokenRotationTransactionService transactionService;

    public RefreshTokenRotationService(
            RefreshTokenValidator refreshTokenValidator,
            RefreshTokenGenerator refreshTokenGenerator,
            RefreshTokenRotationTransactionService transactionService
    ) {
        this.refreshTokenValidator = refreshTokenValidator;
        this.refreshTokenGenerator = refreshTokenGenerator;
        this.transactionService = transactionService;
    }

    @Transactional(propagation = Propagation.NEVER)
    public RefreshTokenRotationResult rotate(String rawToken) {
        String validatedToken =
                refreshTokenValidator.validate(rawToken);

        String tokenHash =
                refreshTokenGenerator.hash(validatedToken);

        RefreshTokenRotationOutcome outcome =
                transactionService.rotate(tokenHash);

        if (!outcome.isSuccess()) {
            throw new InvalidRefreshTokenException();
        }

        return outcome.result();
    }
}
