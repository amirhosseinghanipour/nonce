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

// EmailVerificationRepository implements ports.EmailVerificationStore (magic_links with type='email_verification').
type EmailVerificationRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewEmailVerificationRepository(q *db.Queries, pool *pgxpool.Pool) *EmailVerificationRepository {
	return &EmailVerificationRepository{q: q, pool: pool}
}

const (
	createEmailVerificationSQL   = `INSERT INTO magic_links (id, project_id, email, token_hash, expires_at, type, created_at) VALUES ($1, $2, $3, $4, $5, 'email_verification', NOW())`
	getEmailVerificationByHash   = `SELECT project_id, email FROM magic_links WHERE token_hash = $1 AND type = 'email_verification' AND expires_at > NOW() AND used_at IS NULL`
	markEmailVerificationUsedSQL = `UPDATE magic_links SET used_at = NOW() WHERE token_hash = $1 AND type = 'email_verification'`
)

func (r *EmailVerificationRepository) Create(ctx context.Context, projectID domain.ProjectID, email, tokenHash string, expiresAt int64) error {
	_, err := r.pool.Exec(ctx, createEmailVerificationSQL,
		uuid.New(), projectID.UUID, email, tokenHash, time.Unix(expiresAt, 0))
	return err
}

func (r *EmailVerificationRepository) GetByTokenHash(ctx context.Context, tokenHash string) (domain.ProjectID, string, error) {
	var projectID uuid.UUID
	var email string
	err := r.pool.QueryRow(ctx, getEmailVerificationByHash, tokenHash).Scan(&projectID, &email)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.ProjectID{}, "", err
		}
		return domain.ProjectID{}, "", err
	}
	return domain.NewProjectID(projectID), email, nil
}

func (r *EmailVerificationRepository) MarkUsed(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, markEmailVerificationUsedSQL, tokenHash)
	return err
}

var _ ports.EmailVerificationStore = (*EmailVerificationRepository)(nil)
