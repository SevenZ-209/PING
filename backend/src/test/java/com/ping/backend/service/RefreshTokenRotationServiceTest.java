
package com.ping.backend.service;

import com.ping.backend.dto.auth.RefreshTokenRotationOutcome;
import com.ping.backend.dto.auth.RefreshTokenRotationResult;
import com.ping.backend.exception.InvalidRefreshRequestException;
import com.ping.backend.exception.InvalidRefreshTokenException;
import com.ping.backend.security.RefreshTokenGenerator;
import com.ping.backend.validation.RefreshTokenValidator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenRotationServiceTest {

    private static final String RAW_TOKEN = "A".repeat(43);

    private static final String TOKEN_HASH = "a".repeat(64);

    private static final String REPLACEMENT_TOKEN = "B".repeat(42) + "A";

    @Mock
    private RefreshTokenGenerator refreshTokenGenerator;

    @Mock
    private RefreshTokenRotationTransactionService transactionService;

    private RefreshTokenRotationService rotationService;

    private RefreshTokenRotationResult rotationResult;

    @BeforeEach
    void setUp() {
        rotationService = new RefreshTokenRotationService(
                new RefreshTokenValidator(),
                refreshTokenGenerator,
                transactionService
        );

        rotationResult = new RefreshTokenRotationResult(
                UUID.randomUUID(),
                UUID.randomUUID(),
                REPLACEMENT_TOKEN,
                Instant.parse("2026-12-01T00:00:00Z"),
                Instant.parse("2027-01-30T00:00:00Z")
        );
    }

    @Test
    void rotate_whenSuccessful_returnsRotationResult() {
        when(refreshTokenGenerator.hash(RAW_TOKEN))
                .thenReturn(TOKEN_HASH);

        when(transactionService.rotate(TOKEN_HASH))
                .thenReturn(
                        RefreshTokenRotationOutcome.success(rotationResult)
                );

        RefreshTokenRotationResult result =
                rotationService.rotate(RAW_TOKEN);

        assertThat(result).isSameAs(rotationResult);

        InOrder inOrder = inOrder(
                refreshTokenGenerator,
                transactionService
        );

        inOrder.verify(refreshTokenGenerator).hash(RAW_TOKEN);

        inOrder.verify(transactionService).rotate(TOKEN_HASH);

        verifyNoMoreInteractions(
                refreshTokenGenerator,
                transactionService
        );
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {
            " ",
            "invalid-token",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB"
    })
    void rotate_whenTokenIsMalformed_throwsException(
            String rawToken
    ) {
        assertThatThrownBy(() ->
                rotationService.rotate(rawToken)
        )
                .isInstanceOf(InvalidRefreshRequestException.class)
                .hasMessage("Invalid refresh token format");

        verifyNoInteractions(
                refreshTokenGenerator,
                transactionService
        );
    }

    @Test
    void rotate_whenOutcomeIsRejected_throwsInvalidRefreshTokenException() {
        when(refreshTokenGenerator.hash(RAW_TOKEN))
                .thenReturn(TOKEN_HASH);

        when(transactionService.rotate(TOKEN_HASH))
                .thenReturn(
                        RefreshTokenRotationOutcome.rejected()
                );

        assertThatThrownBy(() ->
                rotationService.rotate(RAW_TOKEN)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        verify(refreshTokenGenerator).hash(RAW_TOKEN);

        verify(transactionService).rotate(TOKEN_HASH);

        verifyNoMoreInteractions(
                refreshTokenGenerator,
                transactionService
        );
    }

    @Test
    void rotate_whenReuseIsDetected_throwsInvalidRefreshTokenException() {
        when(refreshTokenGenerator.hash(RAW_TOKEN))
                .thenReturn(TOKEN_HASH);

        when(transactionService.rotate(TOKEN_HASH))
                .thenReturn(
                        RefreshTokenRotationOutcome.reuseDetected()
                );

        assertThatThrownBy(() ->
                rotationService.rotate(RAW_TOKEN)
        )
                .isInstanceOf(InvalidRefreshTokenException.class)
                .hasMessage("Invalid or expired refresh token");

        verify(refreshTokenGenerator).hash(RAW_TOKEN);

        verify(transactionService).rotate(TOKEN_HASH);

        verifyNoMoreInteractions(
                refreshTokenGenerator,
                transactionService
        );
    }

    @Test
    void rotate_whenHashingFails_propagatesException() {
        IllegalStateException failure =
                new IllegalStateException("SHA-256 is unavailable");

        when(refreshTokenGenerator.hash(RAW_TOKEN))
                .thenThrow(failure);

        assertThatThrownBy(() ->
                rotationService.rotate(RAW_TOKEN)
        )
                .isSameAs(failure);

        verify(refreshTokenGenerator).hash(RAW_TOKEN);

        verifyNoMoreInteractions(refreshTokenGenerator);

        verifyNoInteractions(transactionService);
    }

    @Test
    void rotate_whenTransactionFails_propagatesException() {
        IllegalStateException failure =
                new IllegalStateException(
                        "Simulated transaction failure"
                );

        when(refreshTokenGenerator.hash(RAW_TOKEN))
                .thenReturn(TOKEN_HASH);

        when(transactionService.rotate(TOKEN_HASH))
                .thenThrow(failure);

        assertThatThrownBy(() ->
                rotationService.rotate(RAW_TOKEN)
        )
                .isSameAs(failure);

        verify(refreshTokenGenerator).hash(RAW_TOKEN);

        verify(transactionService).rotate(TOKEN_HASH);

        verifyNoMoreInteractions(
                refreshTokenGenerator,
                transactionService
        );
    }
}
