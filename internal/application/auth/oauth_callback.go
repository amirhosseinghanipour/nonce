package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/google/uuid"
)

// OAuthUser is the minimal info we get from a provider (Goth user).
type OAuthUser struct {
	Provider       string
	ProviderUserID string
	Email          string
}

// OAuthCallbackResult returns tokens and user after successful OAuth.
type OAuthCallbackResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *domain.User
}

// OAuthCallback gets or creates a user from OAuth identity and issues tokens.
type OAuthCallback struct {
	identityStore ports.IdentityStore
	userRepo      ports.UserRepository
	hasher        ports.PasswordHasher
	issuer        ports.TokenIssuer
	tokenStore    ports.TokenStore
	accessExp     int64
	refreshExp    int64
}

// NewOAuthCallback builds the use case.
func NewOAuthCallback(identityStore ports.IdentityStore, userRepo ports.UserRepository, hasher ports.PasswordHasher, issuer ports.TokenIssuer, tokenStore ports.TokenStore, accessExp, refreshExp int64) *OAuthCallback {
	return &OAuthCallback{
		identityStore: identityStore,
		userRepo:      userRepo,
		hasher:        hasher,
		issuer:        issuer,
		tokenStore:    tokenStore,
		accessExp:     accessExp,
		refreshExp:    refreshExp,
	}
}

// Execute finds or creates user for the OAuth identity and issues tokens.
func (uc *OAuthCallback) Execute(ctx context.Context, projectID domain.ProjectID, oauth OAuthUser) (*OAuthCallbackResult, error) {
	userID, err := uc.identityStore.GetUserIDByProvider(ctx, projectID, oauth.Provider, oauth.ProviderUserID)
	if err == nil {
		// Existing identity: load user and issue tokens
		user, err := uc.userRepo.GetByID(ctx, projectID, userID)
		if err != nil || user == nil {
			return nil, domerrors.ErrUserNotFound
		}
		return uc.issueTokens(ctx, projectID, user)
	}
	if err != domerrors.ErrIdentityNotFound {
		return nil, err
	}
	// New identity: create user and identity (or link to existing user by email)
	user, err := uc.userRepo.GetByEmail(ctx, projectID, oauth.Email)
	if err != nil {
		return nil, err
	}
	if user != nil {
		// User exists with this email: link identity
		if err := uc.identityStore.Create(ctx, projectID, user.ID, oauth.Provider, oauth.ProviderUserID); err != nil {
			return nil, err
		}
		return uc.issueTokens(ctx, projectID, user)
	}
	// Create new user with random password (OAuth-only user)
	id := uuid.New()
	passwordHash, err := uc.hasher.Hash(hex.EncodeToString(id[:]) + "oauth")
	if err != nil {
		return nil, err
	}
	now := time.Now()
	user = &domain.User{
		ID:           domain.NewUserID(id),
		ProjectID:     projectID,
		Email:         oauth.Email,
		PasswordHash:  passwordHash,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if err := uc.userRepo.Create(ctx, user); err != nil {
		return nil, err
	}
	if err := uc.identityStore.Create(ctx, projectID, user.ID, oauth.Provider, oauth.ProviderUserID); err != nil {
		return nil, err
	}
	return uc.issueTokens(ctx, projectID, user)
}

func (uc *OAuthCallback) issueTokens(ctx context.Context, projectID domain.ProjectID, user *domain.User) (*OAuthCallbackResult, error) {
	accessToken, err := uc.issuer.IssueAccessToken(projectID.String(), user.ID.String(), uc.accessExp)
	if err != nil {
		return nil, err
	}
	refreshRaw := make([]byte, 32)
	if _, err := rand.Read(refreshRaw); err != nil {
		return nil, err
	}
	refreshToken := hex.EncodeToString(refreshRaw)
	expiresAt := time.Now().Add(time.Duration(uc.refreshExp) * time.Second).Unix()
	if err := uc.tokenStore.StoreRefreshToken(ctx, projectID, user.ID, refreshToken, expiresAt); err != nil {
		return nil, err
	}
	return &OAuthCallbackResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}
