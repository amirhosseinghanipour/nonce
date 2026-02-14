-- name: CreateOrganization :one
INSERT INTO organizations (id, project_id, name, created_at)
VALUES ($1, $2, $3, $4)
RETURNING id, project_id, name, created_at;

-- name: GetOrganizationByID :one
SELECT id, project_id, name, created_at
FROM organizations
WHERE id = $1 AND project_id = $2;

-- name: ListOrganizationsByProjectID :many
SELECT id, project_id, name, created_at
FROM organizations
WHERE project_id = $1
ORDER BY created_at DESC
LIMIT $2 OFFSET $3;

-- name: ListOrganizationsForUser :many
SELECT o.id, o.project_id, o.name, o.created_at
FROM organizations o
INNER JOIN organization_members m ON m.organization_id = o.id
WHERE o.project_id = $1 AND m.user_id = $2
ORDER BY o.created_at DESC;

-- name: UpdateOrganizationName :exec
UPDATE organizations SET name = $1 WHERE id = $2 AND project_id = $3;
