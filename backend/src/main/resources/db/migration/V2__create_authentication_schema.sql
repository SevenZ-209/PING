
ALTER TABLE users
    ALTER COLUMN password_hash DROP NOT NULL;

ALTER TABLE users
    ADD COLUMN email_verified_at TIMESTAMPTZ;


CREATE TABLE user_identities (
                                 id UUID PRIMARY KEY,
                                 user_id UUID NOT NULL,
                                 provider VARCHAR(30) NOT NULL,
                                 provider_subject VARCHAR(255) NOT NULL,
                                 created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

                                 CONSTRAINT fk_user_identities_user
                                     FOREIGN KEY (user_id)
                                         REFERENCES users(id)
                                         ON DELETE CASCADE,

                                 CONSTRAINT uq_user_identities_provider_subject
                                     UNIQUE (provider, provider_subject),

                                 CONSTRAINT uq_user_identities_user_provider
                                     UNIQUE (user_id, provider),

                                 CONSTRAINT chk_user_identities_provider
                                     CHECK (provider = 'GOOGLE'),

                                 CONSTRAINT chk_user_identities_subject_not_blank
                                     CHECK (LENGTH(TRIM(provider_subject)) > 0)
);


CREATE TABLE auth_sessions (
                               id UUID PRIMARY KEY,
                               user_id UUID NOT NULL,
                               created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                               expires_at TIMESTAMPTZ NOT NULL,
                               revoked_at TIMESTAMPTZ,
                               last_used_at TIMESTAMPTZ,

                               CONSTRAINT fk_auth_sessions_user
                                   FOREIGN KEY (user_id)
                                       REFERENCES users(id)
                                       ON DELETE CASCADE,

                               CONSTRAINT chk_auth_sessions_expiry
                                   CHECK (expires_at > created_at)
);

CREATE INDEX idx_auth_sessions_user_id
    ON auth_sessions(user_id);


CREATE TABLE auth_refresh_tokens (
                                     id UUID PRIMARY KEY,
                                     session_id UUID NOT NULL,
                                     token_hash VARCHAR(64) NOT NULL,
                                     created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                     expires_at TIMESTAMPTZ NOT NULL,
                                     consumed_at TIMESTAMPTZ,

                                     CONSTRAINT fk_auth_refresh_tokens_session
                                         FOREIGN KEY (session_id)
                                             REFERENCES auth_sessions(id)
                                             ON DELETE CASCADE,

                                     CONSTRAINT uq_auth_refresh_tokens_hash
                                         UNIQUE (token_hash),

                                     CONSTRAINT chk_auth_refresh_tokens_expiry
                                         CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX uq_auth_refresh_tokens_unconsumed_session
    ON auth_refresh_tokens(session_id)
    WHERE consumed_at IS NULL;



CREATE TABLE email_verification_tokens (
                                           id UUID PRIMARY KEY,
                                           user_id UUID NOT NULL,
                                           token_hash VARCHAR(64) NOT NULL,
                                           created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                           expires_at TIMESTAMPTZ NOT NULL,
                                           consumed_at TIMESTAMPTZ,
                                           invalidated_at TIMESTAMPTZ,

                                           CONSTRAINT fk_email_verification_tokens_user
                                               FOREIGN KEY (user_id)
                                                   REFERENCES users(id)
                                                   ON DELETE CASCADE,

                                           CONSTRAINT uq_email_verification_tokens_hash
                                               UNIQUE (token_hash),

                                           CONSTRAINT chk_email_verification_tokens_expiry
                                               CHECK (expires_at > created_at),

                                           CONSTRAINT chk_email_verification_tokens_state
                                               CHECK (
                                                   consumed_at IS NULL
                                                       OR invalidated_at IS NULL
                                                   )
);

CREATE UNIQUE INDEX uq_email_verification_current_user
    ON email_verification_tokens(user_id)
    WHERE consumed_at IS NULL
      AND invalidated_at IS NULL;

