package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

const (
	DefaultAccessTokenExpiry  = 900   // 15 min
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
}

type Login struct {
	users       ports.UserRepository
	hasher      ports.PasswordHasher
	issuer      ports.TokenIssuer
	tokenStore  ports.TokenStore
	accessExp   int64
	refreshExp  int64
}

func NewLogin(users ports.UserRepository, hasher ports.PasswordHasher, issuer ports.TokenIssuer, tokenStore ports.TokenStore, accessExp, refreshExp int64) *Login {
	if accessExp <= 0 {
		accessExp = DefaultAccessTokenExpiry
	}
	if refreshExp <= 0 {
		refreshExp = DefaultRefreshTokenExpiry
	}
	return &Login{
		users:      users,
		hasher:     hasher,
		issuer:     issuer,
		tokenStore: tokenStore,
		accessExp:  accessExp,
		refreshExp: refreshExp,
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
	if err := uc.tokenStore.StoreRefreshToken(ctx, input.ProjectID, user.ID, refreshHash, expiresAt); err != nil {
		return nil, err
	}
	return &LoginResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}

// hashForStorage returns a value to store for refresh token lookup.
// TODO: store SHA256(token) instead of plain token.
func hashForStorage(token string) string {
	return token
}
