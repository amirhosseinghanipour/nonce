package postgres

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type TokenStore struct {
	q *db.Queries
}

func NewTokenStore(q *db.Queries) *TokenStore {
	return &TokenStore{q: q}
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, tokenHash string, expiresAt int64) error {
	_, err := s.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID:        uuid.New(),
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
		TokenHash: tokenHash,
		ExpiresAt: time.Unix(expiresAt, 0),
		CreatedAt: time.Now(),
	})
	return err
}

func (s *TokenStore) GetRefreshToken(ctx context.Context, tokenHash string) (projectID domain.ProjectID, userID domain.UserID, err error) {
	r, err := s.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.ProjectID{}, domain.UserID{}, err
		}
		return domain.ProjectID{}, domain.UserID{}, err
	}
	return domain.NewProjectID(r.ProjectID), domain.NewUserID(r.UserID), nil
}

func (s *TokenStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	return s.q.DeleteRefreshTokenByHash(ctx, tokenHash)
}

// Ensure TokenStore implements ports.TokenStore.
var _ ports.TokenStore = (*TokenStore)(nil)
