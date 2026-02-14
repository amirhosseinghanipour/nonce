package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

type RefreshInput struct {
	RefreshToken string
}

type RefreshResult struct {
	AccessToken  string
	RefreshToken string
	ExpiresIn    int64
}

type Refresh struct {
	issuer     ports.TokenIssuer
	tokenStore ports.TokenStore
	accessExp  int64
	refreshExp int64
}

func NewRefresh(issuer ports.TokenIssuer, tokenStore ports.TokenStore, accessExp, refreshExp int64) *Refresh {
	if accessExp <= 0 {
		accessExp = DefaultAccessTokenExpiry
	}
	if refreshExp <= 0 {
		refreshExp = DefaultRefreshTokenExpiry
	}
	return &Refresh{
		issuer:     issuer,
		tokenStore: tokenStore,
		accessExp:  accessExp,
		refreshExp: refreshExp,
	}
}

func (uc *Refresh) Execute(ctx context.Context, input RefreshInput) (*RefreshResult, error) {
	if input.RefreshToken == "" {
		return nil, errors.ErrInvalidToken
	}
	tokenHash := hashForStorage(input.RefreshToken)
	info, err := uc.tokenStore.GetRefreshToken(ctx, tokenHash)
	if err != nil {
		return nil, errors.ErrInvalidToken
	}
	// Reuse detection: token was already rotated (used once before). Revoke entire session.
	if info.RevokedAt != nil {
		_ = uc.tokenStore.RevokeSession(ctx, info.SessionID, ports.RevokedReasonSuspiciousActivity)
		return nil, errors.ErrRefreshTokenReuse
	}
	if time.Now().After(info.ExpiresAt) {
		return nil, errors.ErrInvalidToken
	}
	// Mark this token as rotated (used), then create new token with parent_id = this id.
	if err := uc.tokenStore.MarkTokenRotated(ctx, info.TokenID); err != nil {
		return nil, err
	}
	accessToken, err := uc.issuer.IssueAccessToken(info.ProjectID.String(), info.UserID.String(), uc.accessExp)
	if err != nil {
		return nil, err
	}
	newRefreshRaw := make([]byte, 32)
	if _, err := rand.Read(newRefreshRaw); err != nil {
		return nil, err
	}
	newRefresh := hex.EncodeToString(newRefreshRaw)
	expiresAt := time.Now().Add(time.Duration(uc.refreshExp) * time.Second).Unix()
	parentID := info.TokenID
	if err := uc.tokenStore.StoreRefreshToken(ctx, info.ProjectID, info.UserID, info.SessionID, &parentID, hashForStorage(newRefresh), expiresAt); err != nil {
		return nil, err
	}
	return &RefreshResult{
		AccessToken:  accessToken,
		RefreshToken: newRefresh,
		ExpiresIn:    uc.accessExp,
	}, nil
}
