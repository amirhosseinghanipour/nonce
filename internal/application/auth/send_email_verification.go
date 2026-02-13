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

// SendEmailVerificationInput is projectID + email (e.g. from JWT /users/me or signup).
type SendEmailVerificationInput struct {
	ProjectID domain.ProjectID
	Email     string
}

// SendEmailVerificationResult is empty on success.
type SendEmailVerificationResult struct{}

// SendEmailVerification creates a verification token, stores its hash, and enqueues the email.
type SendEmailVerification struct {
	store    ports.EmailVerificationStore
	userRepo ports.UserRepository
	enqueuer ports.TaskEnqueuer
	baseURL  string
	expiry   int64
}

// NewSendEmailVerification builds the use case.
func NewSendEmailVerification(store ports.EmailVerificationStore, userRepo ports.UserRepository, enqueuer ports.TaskEnqueuer, baseURL string, expirySecs int64) *SendEmailVerification {
	if expirySecs <= 0 {
		expirySecs = 86400
	}
	return &SendEmailVerification{
		store:    store,
		userRepo: userRepo,
		enqueuer: enqueuer,
		baseURL:  baseURL,
		expiry:   expirySecs,
	}
}

// Execute creates the token and enqueues the verification email. Returns error only on internal failure.
func (uc *SendEmailVerification) Execute(ctx context.Context, input SendEmailVerificationInput) (*SendEmailVerificationResult, error) {
	user, err := uc.userRepo.GetByEmail(ctx, input.ProjectID, input.Email)
	if err != nil || user == nil {
		return &SendEmailVerificationResult{}, nil
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	tokenStr := hex.EncodeToString(token)
	hash := sha256Hash(tokenStr)
	expiresAt := time.Now().Add(time.Duration(uc.expiry) * time.Second).Unix()
	if err := uc.store.Create(ctx, input.ProjectID, input.Email, hash, expiresAt); err != nil {
		return nil, err
	}
	verifyURL := fmt.Sprintf("%s?token=%s", uc.baseURL, tokenStr)
	_ = uc.enqueuer.EnqueueSendEmailVerification(ctx, input.ProjectID.String(), input.Email, verifyURL)
	return &SendEmailVerificationResult{}, nil
}
