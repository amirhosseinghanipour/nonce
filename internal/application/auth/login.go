package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

const (
	DefaultAccessTokenExpiry  = 900    // 15 min
	DefaultRefreshTokenExpiry = 604800 // 7 days
)

type LoginInput struct {
	ProjectID domain.ProjectID
	Email     string
	Password  string
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *domain.User
	// MFARequired is true when user has verified TOTP; client must call POST /auth/mfa/verify with mfa_token + code.
	MFARequired  bool
	MFAToken     string
	MFAExpiresIn int64
}

type Login struct {
	users         ports.UserRepository
	hasher        ports.PasswordHasher
	issuer        ports.TokenIssuer
	tokenStore    ports.TokenStore
	totpStore     ports.TOTPStore // optional; if set, login checks TOTP and returns mfa_required
	accessExp     int64
	refreshExp    int64
	mfaPendingExp int64 // expiry for mfa_token (e.g. 300)
}

func NewLogin(users ports.UserRepository, hasher ports.PasswordHasher, issuer ports.TokenIssuer, tokenStore ports.TokenStore, totpStore ports.TOTPStore, accessExp, refreshExp, mfaPendingExp int64) *Login {
	if accessExp <= 0 {
		accessExp = DefaultAccessTokenExpiry
	}
	if refreshExp <= 0 {
		refreshExp = DefaultRefreshTokenExpiry
	}
	if mfaPendingExp <= 0 {
		mfaPendingExp = 300
	}
	return &Login{
		users:         users,
		hasher:        hasher,
		issuer:        issuer,
		tokenStore:    tokenStore,
		totpStore:     totpStore,
		accessExp:     accessExp,
		refreshExp:    refreshExp,
		mfaPendingExp: mfaPendingExp,
	}
}

func (uc *Login) Execute(ctx context.Context, input LoginInput) (*LoginResult, error) {
	user, err := uc.users.GetByEmail(ctx, input.ProjectID, input.Email)
	if err != nil {
		return nil, err
	}
	if user == nil || !uc.hasher.Verify(input.Password, user.PasswordHash) {
		return nil, domerrors.ErrInvalidCredentials
	}
	if uc.totpStore != nil && HasVerifiedTOTP(ctx, uc.totpStore, user.ID, input.ProjectID) {
		mfaToken, err := uc.issuer.IssueMFAPendingToken(input.ProjectID.String(), user.ID.String(), uc.mfaPendingExp)
		if err != nil {
			return nil, err
		}
		return &LoginResult{
			MFARequired:  true,
			MFAToken:     mfaToken,
			MFAExpiresIn: uc.mfaPendingExp,
			User:         user,
		}, nil
	}
	accessToken, err := uc.issuer.IssueAccessToken(input.ProjectID.String(), user.ID.String(), uc.accessExp)
	if err != nil {
		return nil, err
	}
	refreshRaw := make([]byte, 32)
	if _, err := rand.Read(refreshRaw); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshRaw)
	refreshHash := hashForStorage(refreshToken)
	expiresAt := time.Now().Add(time.Duration(uc.refreshExp) * time.Second).Unix()
	if err := uc.tokenStore.StoreRefreshToken(ctx, input.ProjectID, user.ID, nil, refreshHash, expiresAt); err != nil {
		return nil, err
	}
	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}

// hashForStorage returns SHA256(token) hex for refresh token lookup.
func hashForStorage(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
