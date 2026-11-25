ALTER TABLE auth_sessions
    ADD CONSTRAINT chk_auth_sessions_revocation
        CHECK (
            revoked_at IS NULL
                OR revoked_at >= created_at
            );

ALTER TABLE auth_refresh_tokens
    ADD CONSTRAINT chk_auth_refresh_tokens_consumption
        CHECK (
            consumed_at IS NULL
                OR consumed_at >= created_at
            );

CREATE INDEX idx_auth_refresh_tokens_session_id
    ON auth_refresh_tokens(session_id);