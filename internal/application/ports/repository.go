package ports

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// UserRepository defines persistence for users (project-scoped).
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, projectID domain.ProjectID, email string) (*domain.User, error)
	GetByID(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (*domain.User, error)
	List(ctx context.Context, projectID domain.ProjectID, limit, offset int) ([]*domain.User, error)
	UpdatePassword(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, passwordHash string) error
	SetEmailVerified(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error
}

// ProjectRepository defines persistence for projects (tenants).
type ProjectRepository interface {
	GetByID(ctx context.Context, projectID domain.ProjectID) (*domain.Project, error)
	GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*domain.Project, error)
}

// TokenStore defines storage for refresh tokens (Redis or DB).
type TokenStore interface {
	StoreRefreshToken(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, tokenHash string, expiresAt int64) error
	GetRefreshToken(ctx context.Context, tokenHash string) (projectID domain.ProjectID, userID domain.UserID, err error)
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
}

// MagicLinkStore defines storage for passwordless magic links.
type MagicLinkStore interface {
	Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error
	GetByTokenHash(ctx context.Context, tokenHash string) (projectID domain.ProjectID, email string, err error)
	MarkUsed(ctx context.Context, tokenHash string) error
}

// PasswordResetStore defines storage for password-reset tokens (same table as magic_links with type=password_reset).
type PasswordResetStore interface {
	Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error
	GetByTokenHash(ctx context.Context, tokenHash string) (projectID domain.ProjectID, email string, err error)
	MarkUsed(ctx context.Context, tokenHash string) error
}

// EmailVerificationStore defines storage for email verification tokens (magic_links with type=email_verification).
type EmailVerificationStore interface {
	Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error
	GetByTokenHash(ctx context.Context, tokenHash string) (projectID domain.ProjectID, email string, err error)
	MarkUsed(ctx context.Context, tokenHash string) error
}

// TOTPStore defines storage for user TOTP secrets (MFA).
type TOTPStore interface {
	Create(ctx context.Context, userID domain.UserID, projectID domain.ProjectID, secretEncrypted string) error
	GetByUserID(ctx context.Context, userID domain.UserID, projectID domain.ProjectID) (secretEncrypted string, verifiedAt *int64, err error)
	SetVerifiedAt(ctx context.Context, userID domain.UserID, projectID domain.ProjectID) error
}

// IdentityStore defines storage for OAuth/social identities (link user to provider).
// GetUserIDByProvider returns ErrIdentityNotFound when no identity exists.
type IdentityStore interface {
	Create(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, provider, providerUserID string) error
	GetUserIDByProvider(ctx context.Context, projectID domain.ProjectID, provider, providerUserID string) (domain.UserID, error)
}

// WebAuthnCredentialRow is a single stored credential for WebAuthn (ID, PublicKey, SignCount).
type WebAuthnCredentialRow struct {
	ID        []byte
	PublicKey []byte
	SignCount uint32
}

// WebAuthnCredentialStore defines storage for WebAuthn passkey credentials.
type WebAuthnCredentialStore interface {
	Create(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, credentialID, publicKey []byte, signCount uint32) error
	ListByUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]WebAuthnCredentialRow, error)
	UpdateSignCount(ctx context.Context, projectID domain.ProjectID, credentialID []byte, signCount uint32) error
}
