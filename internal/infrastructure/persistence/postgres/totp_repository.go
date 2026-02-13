package postgres

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TOTPRepository implements ports.TOTPStore via raw SQL (user_totp not in sqlc).
type TOTPRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewTOTPRepository(q *db.Queries, pool *pgxpool.Pool) *TOTPRepository {
	return &TOTPRepository{q: q, pool: pool}
}

const (
	createTOTPSQL   = `INSERT INTO user_totp (id, user_id, project_id, secret_encrypted, created_at) VALUES (uuid_generate_v4(), $1, $2, $3, NOW()) ON CONFLICT (user_id) DO UPDATE SET secret_encrypted = EXCLUDED.secret_encrypted, verified_at = NULL`
	getTOTPByUser   = `SELECT secret_encrypted, verified_at FROM user_totp WHERE user_id = $1 AND project_id = $2`
	setTOTPVerified = `UPDATE user_totp SET verified_at = NOW() WHERE user_id = $1 AND project_id = $2`
)

func (r *TOTPRepository) Create(ctx context.Context, userID domain.UserID, projectID domain.ProjectID, secretEncrypted string) error {
	_, err := r.pool.Exec(ctx, createTOTPSQL, userID.UUID, projectID.UUID, secretEncrypted)
	return err
}

func (r *TOTPRepository) GetByUserID(ctx context.Context, userID domain.UserID, projectID domain.ProjectID) (secretEncrypted string, verifiedAt *int64, err error) {
	var v *time.Time
	err = r.pool.QueryRow(ctx, getTOTPByUser, userID.UUID, projectID.UUID).Scan(&secretEncrypted, &v)
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil, nil
		}
		return "", nil, err
	}
	if v != nil {
		epoch := v.Unix()
		verifiedAt = &epoch
	}
	return secretEncrypted, verifiedAt, nil
}

func (r *TOTPRepository) SetVerifiedAt(ctx context.Context, userID domain.UserID, projectID domain.ProjectID) error {
	_, err := r.pool.Exec(ctx, setTOTPVerified, userID.UUID, projectID.UUID)
	return err
}

var _ ports.TOTPStore = (*TOTPRepository)(nil)
