package auth

import (
	"context"

	"github.com/pquerna/otp/totp"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// VerifyTOTPInput is the input for verifying a TOTP code (enables MFA).
type VerifyTOTPInput struct {
	UserID    domain.UserID
	ProjectID domain.ProjectID
	Code      string // 6-digit code from authenticator app
}

// VerifyTOTP validates the code and marks TOTP as verified.
type VerifyTOTP struct {
	totpStore ports.TOTPStore
}

// NewVerifyTOTP builds the use case.
func NewVerifyTOTP(totpStore ports.TOTPStore) *VerifyTOTP {
	return &VerifyTOTP{totpStore: totpStore}
}

// Execute validates the code against the stored secret and sets verified_at.
func (uc *VerifyTOTP) Execute(ctx context.Context, input VerifyTOTPInput) error {
	secret, verifiedAt, err := uc.totpStore.GetByUserID(ctx, input.UserID, input.ProjectID)
	if err != nil {
		return err
	}
	if secret == "" {
		return ErrTOTPNotSetup
	}
	if verifiedAt != nil {
		return ErrTOTPAlreadyVerified
	}
	valid := totp.Validate(input.Code, secret)
	if !valid {
		return ErrTOTPInvalidCode
	}
	return uc.totpStore.SetVerifiedAt(ctx, input.UserID, input.ProjectID)
}

// HasVerifiedTOTP returns true if the user has TOTP set up and verified (for login MFA check).
func HasVerifiedTOTP(ctx context.Context, totpStore ports.TOTPStore, userID domain.UserID, projectID domain.ProjectID) bool {
	_, verifiedAt, err := totpStore.GetByUserID(ctx, userID, projectID)
	if err != nil || verifiedAt == nil {
		return false
	}
	return true
}

// ValidateTOTPCode validates a code for the user (used at MFA verify step).
func ValidateTOTPCode(ctx context.Context, totpStore ports.TOTPStore, userID domain.UserID, projectID domain.ProjectID, code string) bool {
	secret, verifiedAt, err := totpStore.GetByUserID(ctx, userID, projectID)
	if err != nil || secret == "" || verifiedAt == nil {
		return false
	}
	return totp.Validate(code, secret)
}

// ErrTOTP* are domain errors for TOTP (define in domain/errors or here).
var (
	ErrTOTPNotSetup         = &totpError{"totp not setup"}
	ErrTOTPAlreadyVerified  = &totpError{"totp already verified"}
	ErrTOTPInvalidCode      = &totpError{"invalid totp code"}
)

type totpError struct{ msg string }

func (e *totpError) Error() string { return e.msg }
