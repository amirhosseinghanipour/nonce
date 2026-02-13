package auth

import (
	"context"
	"regexp"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/google/uuid"
)

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

type RegisterUserInput struct {
	ProjectID domain.ProjectID
	Email     string
	Password  string
}

type RegisterUserResult struct {
	User *domain.User
}

type RegisterUser struct {
	users   ports.UserRepository
	hasher  ports.PasswordHasher
}

func NewRegisterUser(users ports.UserRepository, hasher ports.PasswordHasher) *RegisterUser {
	return &RegisterUser{users: users, hasher: hasher}
}

func (uc *RegisterUser) Execute(ctx context.Context, input RegisterUserInput) (*RegisterUserResult, error) {
	if !emailRegex.MatchString(input.Email) {
		return nil, domerrors.ErrInvalidCredentials
	}
	existing, err := uc.users.GetByEmail(ctx, input.ProjectID, input.Email)
	if err != nil {
		return nil, err
	}
	if existing != nil {
		return nil, domerrors.ErrUserExists
	}
	hash, err := uc.hasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	user := &domain.User{
		ID:           domain.NewUserID(uuid.New()),
		ProjectID:    input.ProjectID,
		Email:        input.Email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := uc.users.Create(ctx, user); err != nil {
		return nil, err
	}
	return &RegisterUserResult{User: user}, nil
}
