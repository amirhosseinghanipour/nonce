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

// PasswordResetRepository implements ports.PasswordResetStore (magic_links with type='password_reset').
type PasswordResetRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewPasswordResetRepository(q *db.Queries, pool *pgxpool.Pool) *PasswordResetRepository {
	return &PasswordResetRepository{q: q, pool: pool}
}

const (
	createPasswordResetSQL   = `INSERT INTO magic_links (id, project_id, email, token_hash, expires_at, type, created_at) VALUES ($1, $2, $3, $4, $5, 'password_reset', NOW())`
	getPasswordResetByHash   = `SELECT project_id, email FROM magic_links WHERE token_hash = $1 AND type = 'password_reset' AND expires_at > NOW() AND used_at IS NULL`
	markPasswordResetUsedSQL = `UPDATE magic_links SET used_at = NOW() WHERE token_hash = $1 AND type = 'password_reset'`
)

func (r *PasswordResetRepository) Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error {
	_, err := r.pool.Exec(ctx, createPasswordResetSQL,
		uuid.New(), projectID.UUID, email, tokenHash, time.Unix(expiresAt, 0))
	return err
}

func (r *PasswordResetRepository) GetByTokenHash(ctx context.Context, tokenHash string) (domain.ProjectID, string, error) {
	var projectID uuid.UUID
	var email string
	err := r.pool.QueryRow(ctx, getPasswordResetByHash, tokenHash).Scan(&projectID, &email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.ProjectID{}, "", err
		}
		return domain.ProjectID{}, "", err
	}
	return domain.NewProjectID(projectID), email, nil
}

func (r *PasswordResetRepository) MarkUsed(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, markPasswordResetUsedSQL, tokenHash)
	return err
}

var _ ports.PasswordResetStore = (*PasswordResetRepository)(nil)
