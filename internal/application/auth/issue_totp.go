package auth

import (
	"context"

	"github.com/pquerna/otp/totp"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// IssueTOTPInput is the input for setting up TOTP (caller must be authenticated).
type IssueTOTPInput struct {
	UserID    domain.UserID
	ProjectID domain.ProjectID
	Issuer    string // e.g. "Nonce" or app name
	Account   string // e.g. user email
}

// IssueTOTPResult returns the secret and QR URL for the authenticator app.
type IssueTOTPResult struct {
	Secret string // base32 secret
	URL    string // otpauth://totp/... for QR code
}

// IssueTOTP generates a TOTP secret, stores it (unverified), and returns secret + URL.
type IssueTOTP struct {
	totpStore ports.TOTPStore
}

// NewIssueTOTP builds the use case.
func NewIssueTOTP(totpStore ports.TOTPStore) *IssueTOTP {
	return &IssueTOTP{totpStore: totpStore}
}

// Execute creates a new TOTP secret and stores it. User must call VerifyTOTP to enable MFA.
func (uc *IssueTOTP) Execute(ctx context.Context, input IssueTOTPInput) (*IssueTOTPResult, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      input.Issuer,
		AccountName: input.Account,
	})
	if err != nil {
		return nil, err
	}
	secret := key.Secret()
	if err := uc.totpStore.Create(ctx, input.UserID, input.ProjectID, secret); err != nil {
		return nil, err
	}
	return &IssueTOTPResult{
		Secret: secret,
		URL:   key.URL(),
	}, nil
}
