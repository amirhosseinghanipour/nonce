-- name: AddOrganizationMember :one
INSERT INTO organization_members (organization_id, user_id, role, created_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (organization_id, user_id) DO UPDATE SET role = EXCLUDED.role
RETURNING organization_id, user_id, role, created_at;

-- name: RemoveOrganizationMember :exec
DELETE FROM organization_members WHERE organization_id = $1 AND user_id = $2;

-- name: GetOrganizationMember :one
SELECT organization_id, user_id, role, created_at
FROM organization_members
WHERE organization_id = $1 AND user_id = $2;

-- name: ListOrganizationMembers :many
SELECT organization_id, user_id, role, created_at
FROM organization_members
WHERE organization_id = $1
ORDER BY created_at ASC;

-- name: GetUserRoleInOrganization :one
SELECT role FROM organization_members WHERE organization_id = $1 AND user_id = $2;
