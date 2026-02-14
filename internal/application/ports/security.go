package ports

// PasswordHasher hashes and verifies passwords (Argon2id).
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

// TokenIssuer signs and validates JWTs (RS256). Org-scoped tokens include org_id and role.
type TokenIssuer interface {
	IssueAccessToken(projectID, userID string, expiresInSeconds int64) (string, error)
	// IssueAccessTokenWithOrg issues a token with org context (org_id, role) for org-scoped access.
	IssueAccessTokenWithOrg(projectID, userID, orgID, role string, expiresInSeconds int64) (string, error)
	// ValidateAccessToken returns projectID, userID, and orgID/role when org-scoped (empty otherwise).
	ValidateAccessToken(tokenString string) (projectID, userID, orgID, role string, err error)
	IssueMFAPendingToken(projectID, userID string, expiresInSeconds int64) (string, error)
	ValidateMFAPendingToken(tokenString string) (projectID, userID string, err error)
}
