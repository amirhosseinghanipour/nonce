package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// HTTPEmitter sends audit events to an HTTP endpoint via POST JSON.
type HTTPEmitter struct {
	client  *http.Client
	url     string
	headers map[string]string
}

// HTTPEmitterOption configures HTTPEmitter.
type HTTPEmitterOption func(*HTTPEmitter)

// WithClient sets the HTTP client (default: 10s timeout).
func WithClient(c *http.Client) HTTPEmitterOption {
	return func(e *HTTPEmitter) {
		e.client = c
	}
}

// WithHeader sets a header sent on every request (e.g. Authorization, X-API-Key).
func WithHeader(key, value string) HTTPEmitterOption {
	return func(e *HTTPEmitter) {
		if e.headers == nil {
			e.headers = make(map[string]string)
		}
		e.headers[key] = value
	}
}

// NewHTTPEmitter returns a WebhookEmitter that POSTs AuditEvent as JSON to url.
func NewHTTPEmitter(url string, opts ...HTTPEmitterOption) *HTTPEmitter {
	e := &HTTPEmitter{
		client: &http.Client{Timeout: 10 * time.Second},
		url:    url,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Emit implements ports.WebhookEmitter.
func (e *HTTPEmitter) Emit(ctx context.Context, event ports.AuditEvent) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &emitError{status: resp.StatusCode}
	}
	return nil
}

type emitError struct {
	status int
}

func (e *emitError) Error() string {
	return "webhook endpoint returned non-2xx status"
}

var _ ports.WebhookEmitter = (*HTTPEmitter)(nil)
