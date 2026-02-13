package auth

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

// VerifyEmailInput is the token from the verification link.
type VerifyEmailInput struct {
	Token string
}

// VerifyEmailResult is empty on success.
type VerifyEmailResult struct{}

// VerifyEmail looks up the token, finds the user, sets email_verified_at, and marks token used.
type VerifyEmail struct {
	store    ports.EmailVerificationStore
	userRepo ports.UserRepository
}

// NewVerifyEmail builds the use case.
func NewVerifyEmail(store ports.EmailVerificationStore, userRepo ports.UserRepository) *VerifyEmail {
	return &VerifyEmail{store: store, userRepo: userRepo}
}

// Execute validates the token and marks the user's email as verified.
func (uc *VerifyEmail) Execute(ctx context.Context, input VerifyEmailInput) (*VerifyEmailResult, error) {
	hash := sha256Hash(input.Token)
	projectID, email, err := uc.store.GetByTokenHash(ctx, hash)
	if err != nil {
		return nil, domerrors.ErrEmailVerificationInvalid
	}
	user, err := uc.userRepo.GetByEmail(ctx, projectID, email)
	if err != nil || user == nil {
		return nil, domerrors.ErrEmailVerificationInvalid
	}
	if err := uc.userRepo.SetEmailVerified(ctx, projectID, user.ID); err != nil {
		return nil, err
	}
	if err := uc.store.MarkUsed(ctx, hash); err != nil {
		return nil, err
	}
	return &VerifyEmailResult{}, nil
}
