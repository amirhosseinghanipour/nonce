package ports

import "context"

// AuditEvent is a single audit event for logging or webhooks.
type AuditEvent struct {
	Event     string // event type: user.signup, user.login, auth.refresh, etc.
	ProjectID string
	UserID    string
	IP        string
	Success   bool
	Err       string
}

// WebhookEmitter sends audit events to an external endpoint. TODO: implement.
type WebhookEmitter interface {
	Emit(ctx context.Context, event AuditEvent) error
}
