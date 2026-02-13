package ports

// PasswordHasher hashes and verifies passwords (Argon2id).
type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(password, hash string) bool
}

// TokenIssuer signs and validates JWTs (RS256).
type TokenIssuer interface {
	IssueAccessToken(projectID, userID string, expiresInSeconds int64) (string, error)
	ValidateAccessToken(tokenString string) (projectID, userID string, err error)
}
