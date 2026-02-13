package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// ForgotPasswordInput for requesting a password reset email.
type ForgotPasswordInput struct {
	ProjectID domain.ProjectID
	Email     string
}

// ForgotPasswordResult returns nothing; email is sent async (or noop if no user).
type ForgotPasswordResult struct{}

// ForgotPassword creates a reset token, stores its hash, and enqueues sending the email.
// Does not reveal whether the email exists (always 202).
type ForgotPassword struct {
	resetStore ports.PasswordResetStore
	userRepo   ports.UserRepository
	enqueuer   ports.TaskEnqueuer
	baseURL    string
	expirySecs int64
}

// NewForgotPassword builds the use case.
func NewForgotPassword(resetStore ports.PasswordResetStore, userRepo ports.UserRepository, enqueuer ports.TaskEnqueuer, baseURL string, expirySecs int64) *ForgotPassword {
	if expirySecs <= 0 {
		expirySecs = 3600
	}
	return &ForgotPassword{
		resetStore: resetStore,
		userRepo:   userRepo,
		enqueuer:   enqueuer,
		baseURL:    baseURL,
		expirySecs: expirySecs,
	}
}

// Execute creates the reset token and enqueues the email. If email is not found, we still return success (no info leak).
func (uc *ForgotPassword) Execute(ctx context.Context, input ForgotPasswordInput) (*ForgotPasswordResult, error) {
	user, err := uc.userRepo.GetByEmail(ctx, input.ProjectID, input.Email)
	if err != nil || user == nil {
		return &ForgotPasswordResult{}, nil
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	tokenStr := hex.EncodeToString(token)
	hash := sha256Hash(tokenStr)
	expiresAt := time.Now().Add(time.Duration(uc.expirySecs) * time.Second).Unix()
	if err := uc.resetStore.Create(ctx, input.ProjectID, input.Email, hash, expiresAt); err != nil {
		return nil, err
	}
	resetURL := fmt.Sprintf("%s?token=%s", uc.baseURL, tokenStr)
	_ = uc.enqueuer.EnqueueSendPasswordReset(ctx, input.ProjectID.String(), input.Email, resetURL)
	return &ForgotPasswordResult{}, nil
}
