package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/google/uuid"
)

// SignInAnonymousInput is the project ID (from tenant context).
type SignInAnonymousInput struct {
	ProjectID domain.ProjectID
}

// SignInAnonymousResult returns tokens and the anonymous user (no MFA for anonymous).
type SignInAnonymousResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *domain.User
}

// SignInAnonymous creates an anonymous user and issues tokens.
type SignInAnonymous struct {
	users      ports.UserRepository
	issuer     ports.TokenIssuer
	tokenStore ports.TokenStore
	accessExp  int64
	refreshExp int64
}

// NewSignInAnonymous builds the use case.
func NewSignInAnonymous(users ports.UserRepository, issuer ports.TokenIssuer, tokenStore ports.TokenStore, accessExp, refreshExp int64) *SignInAnonymous {
	if accessExp <= 0 {
		accessExp = DefaultAccessTokenExpiry
	}
	if refreshExp <= 0 {
		refreshExp = DefaultRefreshTokenExpiry
	}
	return &SignInAnonymous{
		users:      users,
		issuer:     issuer,
		tokenStore: tokenStore,
		accessExp:  accessExp,
		refreshExp: refreshExp,
	}
}

// Execute creates the anonymous user and returns tokens.
func (uc *SignInAnonymous) Execute(ctx context.Context, input SignInAnonymousInput) (*SignInAnonymousResult, error) {
	id := uuid.New()
	now := time.Now()
	// Synthetic email unique per user so (project_id, email) remains unique; never exposed to clients.
	email := fmt.Sprintf("anon_%s@anonymous.local", id.String())
	// Random password hash (anonymous users never log in with password).
	pwBytes := make([]byte, 32)
	if _, err := rand.Read(pwBytes); err != nil {
		return nil, err
	}
	passwordHash := hex.EncodeToString(pwBytes)
	user := &domain.User{
		ID:           domain.NewUserID(id),
		ProjectID:    input.ProjectID,
		Email:        email,
		PasswordHash: passwordHash,
		CreatedAt:    now,
		UpdatedAt:    now,
		IsAnonymous:  true,
	}
	if err := uc.users.Create(ctx, user); err != nil {
		return nil, err
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
	sessionID, err := uc.tokenStore.CreateSession(ctx, input.ProjectID, user.ID)
	if err != nil {
		return nil, err
	}
	if err := uc.tokenStore.StoreRefreshToken(ctx, input.ProjectID, user.ID, sessionID, nil, refreshHash, expiresAt); err != nil {
		return nil, err
	}
	return &SignInAnonymousResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}
