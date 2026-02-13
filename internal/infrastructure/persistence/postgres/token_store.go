package postgres

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

const revokeTokenAndDescendantsSQL = `
WITH RECURSIVE descendants AS (
	SELECT id FROM refresh_tokens WHERE id = $1
	UNION ALL
	SELECT r.id FROM refresh_tokens r
	INNER JOIN descendants d ON r.parent_id = d.id
)
UPDATE refresh_tokens SET revoked_at = COALESCE(revoked_at, NOW())
WHERE id IN (SELECT id FROM descendants);
`

type TokenStore struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewTokenStore(q *db.Queries, pool *pgxpool.Pool) *TokenStore {
	return &TokenStore{q: q, pool: pool}
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, parentTokenID *string, tokenHash string, expiresAt int64) error {
	var parentID pgtype.UUID
	if parentTokenID != nil && *parentTokenID != "" {
		if id, err := uuid.Parse(*parentTokenID); err == nil {
			var b [16]byte
			copy(b[:], id[:])
			parentID = pgtype.UUID{Bytes: b, Valid: true}
		}
	}
	_, err := s.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID:        uuid.New(),
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
		TokenHash: tokenHash,
		ExpiresAt: time.Unix(expiresAt, 0),
		CreatedAt: time.Now(),
		ParentID:  parentID,
	})
	return err
}

func (s *TokenStore) GetRefreshToken(ctx context.Context, tokenHash string) (*ports.RefreshTokenInfo, error) {
	r, err := s.q.GetRefreshTokenByHash(ctx, tokenHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, err
		}
		return nil, err
	}
	info := &ports.RefreshTokenInfo{
		ProjectID: domain.NewProjectID(r.ProjectID),
		UserID:    domain.NewUserID(r.UserID),
		TokenID:   r.ID.String(),
		ExpiresAt: r.ExpiresAt,
	}
	if r.RevokedAt.Valid {
		t := r.RevokedAt.Time
		info.RevokedAt = &t
	}
	return info, nil
}

func (s *TokenStore) MarkTokenRotated(ctx context.Context, tokenID string) error {
	id, err := uuid.Parse(tokenID)
	if err != nil {
		return err
	}
	return s.q.SetRefreshTokenRevoked(ctx, id)
}

func (s *TokenStore) RevokeTokenAndDescendants(ctx context.Context, tokenID string) error {
	id, err := uuid.Parse(tokenID)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, revokeTokenAndDescendantsSQL, id)
	return err
}

func (s *TokenStore) RevokeRefreshToken(ctx context.Context, tokenHash string) error {
	info, err := s.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil // already gone or invalid
		}
		return err
	}
	return s.MarkTokenRotated(ctx, info.TokenID)
}

// Ensure TokenStore implements ports.TokenStore.
var _ ports.TokenStore = (*TokenStore)(nil)
