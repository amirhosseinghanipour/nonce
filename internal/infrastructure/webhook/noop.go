package webhook

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// NoopEmitter is a no-op webhook emitter when no webhook URL is configured.
type NoopEmitter struct{}

// NewNoopEmitter returns a WebhookEmitter that discards all events.
func NewNoopEmitter() *NoopEmitter {
	return &NoopEmitter{}
}

// Emit implements ports.WebhookEmitter.
func (e *NoopEmitter) Emit(ctx context.Context, event ports.AuditEvent) error {
	return nil
}

var _ ports.WebhookEmitter = (*NoopEmitter)(nil)
