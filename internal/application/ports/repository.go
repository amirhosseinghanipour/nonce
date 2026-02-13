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
