-- name: CreateSession :one
INSERT INTO sessions (id, project_id, user_id, created_at)
VALUES ($1, $2, $3, $4)
RETURNING id, project_id, user_id, created_at, revoked_at, revoked_reason;

-- name: GetSessionByID :one
SELECT id, project_id, user_id, created_at, revoked_at, revoked_reason
FROM sessions
WHERE id = $1;

-- name: ListSessionsByUser :many
SELECT id, project_id, user_id, created_at, revoked_at, revoked_reason
FROM sessions
WHERE project_id = $1 AND user_id = $2
ORDER BY created_at DESC;

-- name: RevokeSessionByID :exec
UPDATE sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoked_reason = $2 WHERE id = $1;

-- name: RevokeAllRefreshTokensInSession :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, NOW()) WHERE session_id = $1;

-- name: RevokeRefreshTokensByUserSessions :exec
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, NOW())
WHERE session_id IN (SELECT s.id FROM sessions s WHERE s.project_id = $1 AND s.user_id = $2);

-- name: RevokeSessionsByUser :exec
UPDATE sessions SET revoked_at = COALESCE(revoked_at, NOW()), revoked_reason = $3 WHERE project_id = $1 AND user_id = $2;
