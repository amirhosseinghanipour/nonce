package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
)

// IdentityRepository implements ports.IdentityStore via raw SQL (identities not in sqlc).
type IdentityRepository struct {
	q    *db.Queries
	pool *pgxpool.Pool
}

func NewIdentityRepository(q *db.Queries, pool *pgxpool.Pool) *IdentityRepository {
	return &IdentityRepository{q: q, pool: pool}
}

const (
	createIdentitySQL       = `INSERT INTO identities (id, project_id, user_id, provider, provider_user_id, created_at) VALUES (uuid_generate_v4(), $1, $2, $3, $4, NOW())`
	getUserIDByProviderSQL  = `SELECT user_id FROM identities WHERE project_id = $1 AND provider = $2 AND provider_user_id = $3`
)

func (r *IdentityRepository) Create(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, provider, providerUserID string) error {
	_, err := r.pool.Exec(ctx, createIdentitySQL, projectID.UUID, userID.UUID, provider, providerUserID)
	return err
}

func (r *IdentityRepository) GetUserIDByProvider(ctx context.Context, projectID domain.ProjectID, provider, providerUserID string) (domain.UserID, error) {
	var id uuid.UUID
	err := r.pool.QueryRow(ctx, getUserIDByProviderSQL, projectID.UUID, provider, providerUserID).Scan(&id)
	if err != nil {
		if err == pgx.ErrNoRows {
			return domain.UserID{}, domerrors.ErrIdentityNotFound
		}
		return domain.UserID{}, err
	}
	return domain.NewUserID(id), nil
}

var _ ports.IdentityStore = (*IdentityRepository)(nil)
