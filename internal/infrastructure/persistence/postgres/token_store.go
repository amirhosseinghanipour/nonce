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

func (s *TokenStore) CreateSession(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (string, error) {
	id := uuid.New()
	_, err := s.q.CreateSession(ctx, db.CreateSessionParams{
		ID:        id,
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
		CreatedAt: time.Now(),
	})
	if err != nil {
		return "", err
	}
	return id.String(), nil
}

func (s *TokenStore) StoreRefreshToken(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, sessionID string, parentTokenID *string, tokenHash string, expiresAt int64) error {
	sessionUUID, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}
	var parentID pgtype.UUID
	if parentTokenID != nil && *parentTokenID != "" {
		if id, err := uuid.Parse(*parentTokenID); err == nil {
			var b [16]byte
			copy(b[:], id[:])
			parentID = pgtype.UUID{Bytes: b, Valid: true}
		}
	}
	_, err = s.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		ID:        uuid.New(),
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
		SessionID: sessionUUID,
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
		SessionID: r.SessionID.String(),
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

func (s *TokenStore) RevokeSession(ctx context.Context, sessionID string, reason string) error {
	id, err := uuid.Parse(sessionID)
	if err != nil {
		return err
	}
	if err := s.q.RevokeAllRefreshTokensInSession(ctx, id); err != nil {
		return err
	}
	return s.q.RevokeSessionByID(ctx, db.RevokeSessionByIDParams{
		ID:            id,
		RevokedReason: pgtype.Text{String: reason, Valid: reason != ""},
	})
}

func (s *TokenStore) RevokeAllSessionsForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, reason string) error {
	if err := s.q.RevokeRefreshTokensByUserSessions(ctx, db.RevokeRefreshTokensByUserSessionsParams{
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
	}); err != nil {
		return err
	}
	return s.q.RevokeSessionsByUser(ctx, db.RevokeSessionsByUserParams{
		ProjectID:     projectID.UUID,
		UserID:        userID.UUID,
		RevokedReason: pgtype.Text{String: reason, Valid: reason != ""},
	})
}

func (s *TokenStore) ListSessionsForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]ports.SessionInfo, error) {
	sessions, err := s.q.ListSessionsByUser(ctx, db.ListSessionsByUserParams{
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ports.SessionInfo, 0, len(sessions))
	for _, se := range sessions {
		info := ports.SessionInfo{
			ID:        se.ID.String(),
			CreatedAt: se.CreatedAt,
		}
		if se.RevokedAt.Valid {
			info.RevokedAt = &se.RevokedAt.Time
		}
		if se.RevokedReason.Valid {
			info.RevokedReason = se.RevokedReason.String
		}
		out = append(out, info)
	}
	return out, nil
}

// Ensure TokenStore implements ports.TokenStore.
var _ ports.TokenStore = (*TokenStore)(nil)
