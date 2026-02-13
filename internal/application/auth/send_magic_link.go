package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

// SendMagicLinkInput for passwordless sign-in.
type SendMagicLinkInput struct {
	ProjectID domain.ProjectID
	Email     string
}

// SendMagicLinkResult returns nothing; email is sent async.
type SendMagicLinkResult struct{}

// SendMagicLink creates a magic link token, stores its hash, and enqueues sending the email.
type SendMagicLink struct {
	magicLinkStore ports.MagicLinkStore
	enqueuer       ports.TaskEnqueuer
	baseURL        string
	expirySecs     int64
}

// NewSendMagicLink builds the use case.
func NewSendMagicLink(magicLinkStore ports.MagicLinkStore, enqueuer ports.TaskEnqueuer, baseURL string, expirySecs int64) *SendMagicLink {
	if expirySecs <= 0 {
		expirySecs = 900
	}
	return &SendMagicLink{
		magicLinkStore: magicLinkStore,
		enqueuer:       enqueuer,
		baseURL:        baseURL,
		expirySecs:     expirySecs,
	}
}

// Execute creates the link and enqueues the email.
func (uc *SendMagicLink) Execute(ctx context.Context, input SendMagicLinkInput) (*SendMagicLinkResult, error) {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	tokenStr := hex.EncodeToString(token)
	hash := sha256Hash(tokenStr)
	expiresAt := time.Now().Add(time.Duration(uc.expirySecs) * time.Second).Unix()

	if err := uc.magicLinkStore.Create(ctx, input.ProjectID, input.Email, hash, expiresAt); err != nil {
		return nil, err
	}

	linkURL := fmt.Sprintf("%s?token=%s", uc.baseURL, tokenStr)
	if err := uc.enqueuer.EnqueueSendMagicLink(ctx, input.ProjectID.String(), input.Email, linkURL); err != nil {
		// best-effort; link is already stored
		return &SendMagicLinkResult{}, nil
	}
	return &SendMagicLinkResult{}, nil
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
