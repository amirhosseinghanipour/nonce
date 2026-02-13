package postgres

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MagicLinkRepository implements MagicLinkStore via raw SQL (magic_links not in sqlc).
type MagicLinkRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewMagicLinkRepository(q *db.Queries, pool *pgxpool.Pool) *MagicLinkRepository {
	return &MagicLinkRepository{q: q, pool: pool}
}

const (
	createMagicLinkSQL   = `INSERT INTO magic_links (id, project_id, email, token_hash, expires_at, type, created_at) VALUES ($1, $2, $3, $4, $5, 'magic_link', NOW())`
	getMagicLinkByHash   = `SELECT project_id, email FROM magic_links WHERE token_hash = $1 AND type = 'magic_link' AND expires_at > NOW() AND used_at IS NULL`
	markMagicLinkUsedSQL = `UPDATE magic_links SET used_at = NOW() WHERE token_hash = $1 AND type = 'magic_link'`
)

func (r *MagicLinkRepository) Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error {
	if r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx, createMagicLinkSQL,
		uuid.New(), projectID.UUID, email, tokenHash, time.Unix(expiresAt, 0))
	return err
}

func (r *MagicLinkRepository) GetByTokenHash(ctx context.Context, tokenHash string) (domain.ProjectID, string, error) {
	if r.pool == nil {
		return domain.ProjectID{}, "", pgx.ErrNoRows
	}
	var projectID uuid.UUID
	var email string
	err := r.pool.QueryRow(ctx, getMagicLinkByHash, tokenHash).Scan(&projectID, &email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.ProjectID{}, "", err
		}
		return domain.ProjectID{}, "", err
	}
	return domain.NewProjectID(projectID), email, nil
}

func (r *MagicLinkRepository) MarkUsed(ctx context.Context, tokenHash string) error {
	if r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx, markMagicLinkUsedSQL, tokenHash)
	return err
}

var _ ports.MagicLinkStore = (*MagicLinkRepository)(nil)
