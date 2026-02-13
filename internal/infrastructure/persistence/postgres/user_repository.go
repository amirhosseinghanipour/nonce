package postgres

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/jackc/pgx/v5"
)

type UserRepository struct {
	q *db.Queries
}

func NewUserRepository(q *db.Queries) *UserRepository {
	return &UserRepository{q: q}
}

func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	_, err := r.q.CreateUser(ctx, db.CreateUserParams{
		ID:           user.ID.UUID,
		ProjectID:    user.ProjectID.UUID,
		Email:        user.Email,
		PasswordHash: user.PasswordHash,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	})
	if err != nil {
		return err
	}
	return nil
}

func (r *UserRepository) GetByEmail(ctx context.Context, projectID domain.ProjectID, email string) (*domain.User, error) {
	u, err := r.q.GetUserByEmail(ctx, db.GetUserByEmailParams{ProjectID: projectID.UUID, Email: email})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbUserToDomain(u), nil
}

func (r *UserRepository) GetByID(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) (*domain.User, error) {
	u, err := r.q.GetUserByID(ctx, db.GetUserByIDParams{ProjectID: projectID.UUID, ID: userID.UUID})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbUserToDomain(u), nil
}

func dbUserToDomain(u db.User) *domain.User {
	return &domain.User{
		ID:           domain.NewUserID(u.ID),
		ProjectID:    domain.NewProjectID(u.ProjectID),
		Email:        u.Email,
		PasswordHash: u.PasswordHash,
		CreatedAt:    u.CreatedAt,
		UpdatedAt:    u.UpdatedAt,
	}
}

// Ensure UserRepository implements ports.UserRepository.
var _ ports.UserRepository = (*UserRepository)(nil)
