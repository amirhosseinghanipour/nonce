package ports

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// UserRepository defines persistence for users (project-scoped). Soft delete: use SoftDelete; anonymization and retention use Anonymize and ListDeletedBefore.
type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	GetByEmail(ctx context.Context, projectID domain.ProjectID, email string) (*domain.User, error)
	GetByID(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (*domain.User, error)
	List(ctx context.Context, projectID domain.ProjectID, limit, offset int) ([]*domain.User, error)
	UpdatePassword(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, passwordHash string) error
	SetEmailVerified(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error
	UpdateUserMetadata(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, metadata map[string]interface{}) error
	UpdateAppMetadata(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, metadata map[string]interface{}) error
	SoftDelete(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error
	Anonymize(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error
	ListDeletedBefore(ctx context.Context, threshold time.Time) ([]DeletedUserRef, error)
	HardDelete(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error
}

// DeletedUserRef is a (project_id, user_id) reference for retention/cleanup.
type DeletedUserRef struct {
	ProjectID domain.ProjectID
	UserID    domain.UserID
}

// ProjectRepository defines persistence for projects (tenants).
type ProjectRepository interface {
	Create(ctx context.Context, project *domain.Project) error
	GetByID(ctx context.Context, projectID domain.ProjectID) (*domain.Project, error)
	GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*domain.Project, error)
	UpdateAPIKeyHash(ctx context.Context, projectID domain.ProjectID, apiKeyHash string) error
}

// OrganizationRepository defines persistence for organizations and members (project-scoped, org-first model).
type OrganizationRepository interface {
	Create(ctx context.Context, org *domain.Organization) error
	GetByID(ctx context.Context, projectID domain.ProjectID, orgID domain.OrganizationID) (*domain.Organization, error)
	ListByProject(ctx context.Context, projectID domain.ProjectID, limit, offset int) ([]*domain.Organization, error)
	ListForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]*domain.Organization, error)
	UpdateName(ctx context.Context, projectID domain.ProjectID, orgID domain.OrganizationID, name string) error
	AddMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID, role string) error
	RemoveMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) error
	GetMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) (*domain.OrganizationMember, error)
	GetUserRole(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) (string, error)
	ListMembers(ctx context.Context, orgID domain.OrganizationID) ([]*domain.OrganizationMember, error)
}

// RefreshTokenInfo is returned by GetRefreshToken for reuse detection and rotation.
type RefreshTokenInfo struct {
	ProjectID domain.ProjectID
	UserID    domain.UserID
	SessionID string // UUID of the sessions row (device/session)
	TokenID   string // UUID of the refresh_tokens row
	RevokedAt *time.Time
	ExpiresAt time.Time
}

// Session revoke reasons (for sessions.revoked_reason).
const (
	RevokedReasonAdmin             = "admin"
	RevokedReasonPasswordChange    = "password_change"
	RevokedReasonMFAReset          = "mfa_reset"
	RevokedReasonSuspiciousActivity = "suspicious_activity"
)

// SessionInfo is a row returned by ListSessionsForUser (admin session list).
type SessionInfo struct {
	ID            string
	CreatedAt     time.Time
	RevokedAt     *time.Time
	RevokedReason string
}

// TokenStore defines storage for sessions and refresh tokens.
type TokenStore interface {
	CreateSession(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (sessionID string, err error)
	StoreRefreshToken(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, sessionID string, parentTokenID *string, tokenHash string, expiresAt int64) error
	GetRefreshToken(ctx context.Context, tokenHash string) (*RefreshTokenInfo, error)
	MarkTokenRotated(ctx context.Context, tokenID string) error
	RevokeTokenAndDescendants(ctx context.Context, tokenID string) error
	RevokeRefreshToken(ctx context.Context, tokenHash string) error
	RevokeSession(ctx context.Context, sessionID string, reason string) error
	RevokeAllSessionsForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, reason string) error
	ListSessionsForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]SessionInfo, error)
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
