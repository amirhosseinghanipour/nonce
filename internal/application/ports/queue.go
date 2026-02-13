package ports

import "context"

// TaskEnqueuer enqueues async tasks (email, webhook).
type TaskEnqueuer interface {
	EnqueueSendMagicLink(ctx context.Context, projectID, email, linkURL string) error
	EnqueueSendPasswordReset(ctx context.Context, projectID, email, resetURL string) error
	EnqueueWebhook(ctx context.Context, event string, payload interface{}) error
}
