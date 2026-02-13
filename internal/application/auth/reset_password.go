package auth

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

// ResetPasswordInput is the token from the reset link and the new password.
type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

// ResetPasswordResult returns nothing on success.
type ResetPasswordResult struct{}

// ResetPassword looks up the reset token, finds the user, updates password, and marks token used.
type ResetPassword struct {
	resetStore ports.PasswordResetStore
	userRepo   ports.UserRepository
	hasher     ports.PasswordHasher
}

// NewResetPassword builds the use case.
func NewResetPassword(resetStore ports.PasswordResetStore, userRepo ports.UserRepository, hasher ports.PasswordHasher) *ResetPassword {
	return &ResetPassword{
		resetStore: resetStore,
		userRepo:   userRepo,
		hasher:     hasher,
	}
}

// Execute validates the token, updates the user's password, and marks the token used.
func (uc *ResetPassword) Execute(ctx context.Context, input ResetPasswordInput) (*ResetPasswordResult, error) {
	hash := sha256Hash(input.Token)
	projectID, email, err := uc.resetStore.GetByTokenHash(ctx, hash)
	if err != nil {
		return nil, domerrors.ErrPasswordResetInvalid
	}
	user, err := uc.userRepo.GetByEmail(ctx, projectID, email)
	if err != nil || user == nil {
		return nil, domerrors.ErrPasswordResetInvalid
	}
	newHash, err := uc.hasher.Hash(input.NewPassword)
	if err != nil {
		return nil, err
	}
	if err := uc.userRepo.UpdatePassword(ctx, projectID, user.ID, newHash); err != nil {
		return nil, err
	}
	if err := uc.resetStore.MarkUsed(ctx, hash); err != nil {
		return nil, err
	}
	return &ResetPasswordResult{}, nil
}
