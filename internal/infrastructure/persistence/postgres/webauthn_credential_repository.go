package postgres

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WebAuthnCredentialRepository implements ports.WebAuthnCredentialStore.
type WebAuthnCredentialRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewWebAuthnCredentialRepository(q *db.Queries, pool *pgxpool.Pool) *WebAuthnCredentialRepository {
	return &WebAuthnCredentialRepository{q: q, pool: pool}
}

const (
	createWebAuthnCredSQL  = `INSERT INTO webauthn_credentials (id, user_id, project_id, credential_id, public_key, sign_count, created_at) VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5, NOW())`
	listWebAuthnByUserSQL  = `SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = $1 AND project_id = $2`
	updateWebAuthnCountSQL = `UPDATE webauthn_credentials SET sign_count = $1 WHERE project_id = $2 AND credential_id = $3`
)

func (r *WebAuthnCredentialRepository) Create(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, credentialID, publicKey []byte, signCount uint32) error {
	_, err := r.pool.Exec(ctx, createWebAuthnCredSQL, userID.UUID, projectID.UUID, credentialID, publicKey, int32(signCount))
	return err
}

func (r *WebAuthnCredentialRepository) ListByUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]ports.WebAuthnCredentialRow, error) {
	rows, err := r.pool.Query(ctx, listWebAuthnByUserSQL, userID.UUID, projectID.UUID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ports.WebAuthnCredentialRow
	for rows.Next() {
		var row ports.WebAuthnCredentialRow
		var signCount int32
		if err := rows.Scan(&row.ID, &row.PublicKey, &signCount); err != nil {
			return nil, err
		}
		row.SignCount = uint32(signCount)
		out = append(out, row)
	}
	return out, rows.Err()
}

func (r *WebAuthnCredentialRepository) UpdateSignCount(ctx context.Context, projectID domain.ProjectID, credentialID []byte, signCount uint32) error {
	res, err := r.pool.Exec(ctx, updateWebAuthnCountSQL, int32(signCount), projectID.UUID, credentialID)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

var _ ports.WebAuthnCredentialStore = (*WebAuthnCredentialRepository)(nil)
