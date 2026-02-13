package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	setProjectIDSQL      = `SELECT set_config('app.current_project_id', $1, true)`
	updatePasswordSQL    = `UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND project_id = $3`
	setEmailVerifiedSQL  = `UPDATE users SET email_verified_at = COALESCE(email_verified_at, NOW()) WHERE id = $1 AND project_id = $2`
)

type UserRepository struct {
	q          *db.Queries
	pool       *pgxpool.Pool
	rlsEnabled bool
}

func NewUserRepository(q *db.Queries, pool *pgxpool.Pool, rlsEnabled bool) *UserRepository {
	return &UserRepository{q: q, pool: pool, rlsEnabled: rlsEnabled}
}

func (r *UserRepository) runWithRLS(ctx context.Context, projectID domain.ProjectID, fn func(*db.Queries) error) error {
	if !r.rlsEnabled || r.pool == nil {
		return fn(r.q)
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, setProjectIDSQL, projectID.String()); err != nil {
		return err
	}
	if err := fn(db.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	return r.runWithRLS(ctx, user.ProjectID, func(q *db.Queries) error {
		_, err := q.CreateUser(ctx, db.CreateUserParams{
			ID:           user.ID.UUID,
			ProjectID:    user.ProjectID.UUID,
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
			IsAnonymous:  user.IsAnonymous,
			UserMetadata: metadataMapToBytes(user.UserMetadata),
			AppMetadata:  metadataMapToBytes(user.AppMetadata),
		})
		return err
	})
}

func (r *UserRepository) GetByEmail(ctx context.Context, projectID domain.ProjectID, email string) (*domain.User, error) {
	var u db.User
	err := r.runWithRLS(ctx, projectID, func(q *db.Queries) error {
		var e error
		u, e = q.GetUserByEmail(ctx, db.GetUserByEmailParams{ProjectID: projectID.UUID, Email: email})
		return e
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbUserToDomain(u), nil
}

func (r *UserRepository) GetByID(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (*domain.User, error) {
	var u db.User
	err := r.runWithRLS(ctx, projectID, func(q *db.Queries) error {
		var e error
		u, e = q.GetUserByID(ctx, db.GetUserByIDParams{ProjectID: projectID.UUID, ID: userID.UUID})
		return e
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbUserToDomain(u), nil
}

func (r *UserRepository) List(ctx context.Context, projectID domain.ProjectID, limit, offset int) ([]*domain.User, error) {
	var list []*domain.User
	err := r.runWithRLS(ctx, projectID, func(q *db.Queries) error {
		users, e := q.ListUsersByProjectID(ctx, db.ListUsersByProjectIDParams{
			ProjectID: projectID.UUID,
			Limit:     int32(limit),
			Offset:    int32(offset),
		})
		if e != nil {
			return e
		}
		for _, u := range users {
			list = append(list, dbUserToDomain(u))
		}
		return nil
	})
	return list, err
}

func (r *UserRepository) UpdatePassword(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, passwordHash string) error {
	if r.rlsEnabled && r.pool != nil {
		tx, err := r.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, setProjectIDSQL, projectID.String()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, updatePasswordSQL, passwordHash, userID.UUID, projectID.UUID)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	_, err := r.pool.Exec(ctx, updatePasswordSQL, passwordHash, userID.UUID, projectID.UUID)
	return err
}

func (r *UserRepository) SetEmailVerified(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) error {
	if r.rlsEnabled && r.pool != nil {
		tx, err := r.pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer tx.Rollback(ctx)
		if _, err := tx.Exec(ctx, setProjectIDSQL, projectID.String()); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, setEmailVerifiedSQL, userID.UUID, projectID.UUID)
		if err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	_, err := r.pool.Exec(ctx, setEmailVerifiedSQL, userID.UUID, projectID.UUID)
	return err
}

func (r *UserRepository) UpdateUserMetadata(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, metadata map[string]interface{}) error {
	return r.runWithRLS(ctx, projectID, func(q *db.Queries) error {
		return q.UpdateUserMetadata(ctx, db.UpdateUserMetadataParams{
			UserMetadata: metadataMapToBytes(metadata),
			ProjectID:    projectID.UUID,
			ID:           userID.UUID,
		})
	})
}

func (r *UserRepository) UpdateAppMetadata(ctx context.Context, projectID domain.ProjectID, userID domain.UserID, metadata map[string]interface{}) error {
	return r.runWithRLS(ctx, projectID, func(q *db.Queries) error {
		return q.UpdateAppMetadata(ctx, db.UpdateAppMetadataParams{
			AppMetadata: metadataMapToBytes(metadata),
			ProjectID:   projectID.UUID,
			ID:          userID.UUID,
		})
	})
}

func dbUserToDomain(u db.User) *domain.User {
	var emailVerifiedAt *time.Time
	if u.EmailVerifiedAt.Valid {
		t := u.EmailVerifiedAt.Time
		emailVerifiedAt = &t
	}
	return &domain.User{
		ID:              domain.NewUserID(u.ID),
		ProjectID:       domain.NewProjectID(u.ProjectID),
		Email:           u.Email,
		PasswordHash:    u.PasswordHash,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
		EmailVerifiedAt: emailVerifiedAt,
		IsAnonymous:     u.IsAnonymous,
		UserMetadata:    metadataBytesToMap(u.UserMetadata),
		AppMetadata:     metadataBytesToMap(u.AppMetadata),
	}
}

func metadataBytesToMap(b []byte) map[string]interface{} {
	if len(b) == 0 {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

func metadataMapToBytes(m map[string]interface{}) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, _ := json.Marshal(m)
	return b
}

// Ensure UserRepository implements ports.UserRepository.
var _ ports.UserRepository = (*UserRepository)(nil)
