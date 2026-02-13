package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/google/uuid"
)

// VerifyMFAInput is the input for completing MFA after login returned mfa_required.
type VerifyMFAInput struct {
	MFAToken string // short-lived token from login
	Code     string // 6-digit TOTP code
}

// VerifyMFAResult returns full tokens after successful MFA.
type VerifyMFAResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *domain.User
}

// VerifyMFA validates mfa_token + TOTP code and issues access + refresh tokens.
type VerifyMFA struct {
	issuer      ports.TokenIssuer
	tokenStore  ports.TokenStore
	totpStore   ports.TOTPStore
	users       ports.UserRepository
	accessExp   int64
	refreshExp   int64
}

// NewVerifyMFA builds the use case.
func NewVerifyMFA(issuer ports.TokenIssuer, tokenStore ports.TokenStore, totpStore ports.TOTPStore, users ports.UserRepository, accessExp, refreshExp int64) *VerifyMFA {
	return &VerifyMFA{
		issuer:     issuer,
		tokenStore: tokenStore,
		totpStore:  totpStore,
		users:      users,
		accessExp:  accessExp,
		refreshExp: refreshExp,
	}
}

// Execute validates the MFA token and TOTP code, then issues full tokens.
func (uc *VerifyMFA) Execute(ctx context.Context, input VerifyMFAInput) (*VerifyMFAResult, error) {
	projectIDStr, userIDStr, err := uc.issuer.ValidateMFAPendingToken(input.MFAToken)
	if err != nil {
		return nil, ErrMFATokenInvalid
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		return nil, ErrMFATokenInvalid
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return nil, ErrMFATokenInvalid
	}
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	if !ValidateTOTPCode(ctx, uc.totpStore, uid, pid, input.Code) {
		return nil, ErrTOTPInvalidCode
	}
	user, err := uc.users.GetByID(ctx, pid, uid)
	if err != nil || user == nil {
		return nil, ErrMFATokenInvalid
	}
	accessToken, err := uc.issuer.IssueAccessToken(projectIDStr, userIDStr, uc.accessExp)
	if err != nil {
		return nil, err
	}
	refreshRaw := make([]byte, 32)
	if _, err := rand.Read(refreshRaw); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshRaw)
	refreshHash := refreshToken // TODO: hash for storage
	expiresAt := time.Now().Add(time.Duration(uc.refreshExp) * time.Second).Unix()
	if err := uc.tokenStore.StoreRefreshToken(ctx, pid, uid, refreshHash, expiresAt); err != nil {
		return nil, err
	}
	return &VerifyMFAResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}

var ErrMFATokenInvalid = &mfaError{"invalid or expired mfa token"}

type mfaError struct{ msg string }

func (e *mfaError) Error() string { return e.msg }
