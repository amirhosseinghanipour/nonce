package queue

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// NoopEnqueuer is a no-op enqueuer when Redis/Asynq is not configured.
type NoopEnqueuer struct{}

func NewNoopEnqueuer() *NoopEnqueuer {
	return &NoopEnqueuer{}
}

func (q *NoopEnqueuer) EnqueueSendMagicLink(ctx context.Context, projectID, email, linkURL string) error {
	return nil
}

func (q *NoopEnqueuer) EnqueueSendPasswordReset(ctx context.Context, projectID, email, resetURL string) error {
	return nil
}

func (q *NoopEnqueuer) EnqueueSendEmailVerification(ctx context.Context, projectID, email, verifyURL string) error {
	return nil
}

func (q *NoopEnqueuer) EnqueueWebhook(ctx context.Context, event string, payload interface{}) error {
	return nil
}

var _ ports.TaskEnqueuer = (*NoopEnqueuer)(nil)
