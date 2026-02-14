-- +goose Up
-- Sessions represent a device/login; each has a refresh token chain.
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    revoked_reason TEXT
);

CREATE INDEX idx_sessions_project_user ON sessions(project_id, user_id);
CREATE INDEX idx_sessions_revoked_at ON sessions(revoked_at) WHERE revoked_at IS NOT NULL;

-- Link refresh tokens to a session (token chain lives in one session).
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS session_id UUID REFERENCES sessions(id) ON DELETE CASCADE;

-- Backfill: one session per existing token (1:1) so every token has a session.
WITH tokens_to_backfill AS (
    SELECT id, project_id, user_id, created_at FROM refresh_tokens WHERE session_id IS NULL
),
new_sessions AS (
    INSERT INTO sessions (id, project_id, user_id, created_at)
    SELECT uuid_generate_v4(), project_id, user_id, created_at FROM tokens_to_backfill
    RETURNING id, project_id, user_id, created_at
),
paired AS (
    SELECT t.id AS token_id, s.id AS session_id
    FROM (SELECT id, created_at, row_number() OVER (ORDER BY created_at, id) rn FROM tokens_to_backfill) t
    JOIN (SELECT id, created_at, row_number() OVER (ORDER BY created_at, id) rn FROM new_sessions) s ON t.rn = s.rn
)
UPDATE refresh_tokens rt SET session_id = paired.session_id FROM paired WHERE rt.id = paired.token_id;

ALTER TABLE refresh_tokens ALTER COLUMN session_id SET NOT NULL;
CREATE INDEX idx_refresh_tokens_session_id ON refresh_tokens(session_id);

-- +goose Down
DROP INDEX IF EXISTS idx_refresh_tokens_session_id;
ALTER TABLE refresh_tokens DROP COLUMN IF EXISTS session_id;
DROP TABLE IF EXISTS sessions;
