-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (id, project_id, user_id, token_hash, expires_at, created_at)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING id, project_id, user_id, token_hash, expires_at, created_at;

-- name: GetRefreshTokenByHash :one
SELECT id, project_id, user_id, token_hash, expires_at, created_at
FROM refresh_tokens
WHERE token_hash = $1 AND expires_at > NOW();

-- name: DeleteRefreshTokenByHash :exec
DELETE FROM refresh_tokens WHERE token_hash = $1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens WHERE expires_at <= NOW();
