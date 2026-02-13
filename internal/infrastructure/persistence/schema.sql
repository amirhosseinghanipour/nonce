-- Schema for sqlc (mirrors migrations).
CREATE TABLE projects (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    api_key_hash TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE users (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id),
    email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    email_verified_at TIMESTAMPTZ,
    is_anonymous BOOLEAN NOT NULL DEFAULT false,
    user_metadata JSONB NOT NULL DEFAULT '{}',
    app_metadata JSONB NOT NULL DEFAULT '{}',
    UNIQUE(project_id, email)
);

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(id),
    user_id UUID NOT NULL REFERENCES users(id),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    parent_id UUID REFERENCES refresh_tokens(id),
    revoked_at TIMESTAMPTZ
);
