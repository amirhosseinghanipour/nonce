package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/google/uuid"
)

// VerifyMagicLinkInput contains the token from the link.
type VerifyMagicLinkInput struct {
	Token string
}

// VerifyMagicLinkResult returns tokens and user (same shape as Login).
type VerifyMagicLinkResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
	User         *domain.User
}

// VerifyMagicLink consumes the token, gets or creates the user, and issues tokens.
type VerifyMagicLink struct {
	magicLinkStore ports.MagicLinkStore
	users          ports.UserRepository
	hasher         ports.PasswordHasher
	issuer         ports.TokenIssuer
	tokenStore     ports.TokenStore
	accessExp      int64
	refreshExp     int64
}

// NewVerifyMagicLink builds the use case.
func NewVerifyMagicLink(
	magicLinkStore ports.MagicLinkStore,
	users ports.UserRepository,
	hasher ports.PasswordHasher,
	issuer ports.TokenIssuer,
	tokenStore ports.TokenStore,
	accessExp, refreshExp int64,
) *VerifyMagicLink {
	if accessExp <= 0 {
		accessExp = DefaultAccessTokenExpiry
	}
	if refreshExp <= 0 {
		refreshExp = DefaultRefreshTokenExpiry
	}
	return &VerifyMagicLink{
		magicLinkStore: magicLinkStore,
		users:          users,
		hasher:         hasher,
		issuer:         issuer,
		tokenStore:     tokenStore,
		accessExp:     accessExp,
		refreshExp:    refreshExp,
	}
}

// Execute verifies the token, get-or-creates user, issues tokens.
func (uc *VerifyMagicLink) Execute(ctx context.Context, input VerifyMagicLinkInput) (*VerifyMagicLinkResult, error) {
	if input.Token == "" {
		return nil, domerrors.ErrMagicLinkInvalid
	}
	hash := sha256Hash(input.Token)
	projectID, email, err := uc.magicLinkStore.GetByTokenHash(ctx, hash)
	if err != nil {
		return nil, domerrors.ErrMagicLinkInvalid
	}
	if err := uc.magicLinkStore.MarkUsed(ctx, hash); err != nil {
		return nil, err
	}

	user, err := uc.users.GetByEmail(ctx, projectID, email)
	if err != nil {
		return nil, err
	}
	if user == nil {
		// Create user (passwordless); set a random password so they can't password-login until they set one
		randomPass := make([]byte, 32)
		rand.Read(randomPass)
		passwordHash, _ := uc.hasher.Hash(hex.EncodeToString(randomPass))
		now := time.Now()
		user = &domain.User{
			ID:           domain.NewUserID(uuid.New()),
			ProjectID:    projectID,
			Email:        email,
			PasswordHash: passwordHash,
			CreatedAt:    now,
			UpdatedAt:    now,
		}
		if err := uc.users.Create(ctx, user); err != nil {
			return nil, err
		}
	}

	accessToken, err := uc.issuer.IssueAccessToken(projectID.String(), user.ID.String(), uc.accessExp)
	if err != nil {
		return nil, err
	}
	refreshRaw := make([]byte, 32)
	rand.Read(refreshRaw)
	refreshToken := hex.EncodeToString(refreshRaw)
	expiresAt := time.Now().Add(time.Duration(uc.refreshExp) * time.Second).Unix()
	if err := uc.tokenStore.StoreRefreshToken(ctx, projectID, user.ID, nil, refreshToken, expiresAt); err != nil {
		return nil, err
	}

	return &VerifyMagicLinkResult{
		AccessToken:  accessToken,
		RefreshToken:  refreshToken,
		ExpiresIn:    uc.accessExp,
		User:         user,
	}, nil
}
