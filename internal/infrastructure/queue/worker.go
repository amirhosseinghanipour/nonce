package queue

import (
	"context"
	"encoding/json"

	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
)

// magicLinkPayload matches the JSON enqueued by TaskEnqueuer.EnqueueSendMagicLink.
type magicLinkPayload struct {
	ProjectID string `json:"project_id"`
	Email     string `json:"email"`
	LinkURL   string `json:"link_url"`
}

// passwordResetPayload matches the JSON enqueued by TaskEnqueuer.EnqueueSendPasswordReset.
type passwordResetPayload struct {
	ProjectID string `json:"project_id"`
	Email     string `json:"email"`
	ResetURL  string `json:"reset_url"`
}

// Worker runs Asynq task handlers (e.g. send magic link email).
type Worker struct {
	srv *asynq.Server
	mux *asynq.ServeMux
	log zerolog.Logger
}

// NewWorker creates an Asynq server and registers handlers. Call Run() to start.
func NewWorker(redisOpt asynq.RedisClientOpt, log zerolog.Logger) *Worker {
	srv := asynq.NewServer(redisOpt, asynq.Config{
		Concurrency: 2,
		LogLevel:    asynq.InfoLevel,
	})
	mux := asynq.NewServeMux()
	w := &Worker{srv: srv, mux: mux, log: log}
	mux.HandleFunc(TypeSendMagicLink, w.handleSendMagicLink)
	mux.HandleFunc(TypeSendPasswordReset, w.handleSendPasswordReset)
	mux.HandleFunc(TypeWebhook, w.handleWebhook)
	return w
}

func (w *Worker) handleSendMagicLink(ctx context.Context, t *asynq.Task) error {
	var p magicLinkPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		w.log.Error().Err(err).Msg("magic link task payload invalid")
		return err
	}
	// Dev: log the link; production would send email via SMTP/sendgrid etc.
	w.log.Info().
		Str("project_id", p.ProjectID).
		Str("email", p.Email).
		Str("link_url", p.LinkURL).
		Msg("magic link email (log only; configure SMTP for real email)")
	return nil
}

func (w *Worker) handleSendPasswordReset(ctx context.Context, t *asynq.Task) error {
	var p passwordResetPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		w.log.Error().Err(err).Msg("password reset task payload invalid")
		return err
	}
	w.log.Info().
		Str("project_id", p.ProjectID).
		Str("email", p.Email).
		Str("reset_url", p.ResetURL).
		Msg("password reset email (log only; configure SMTP for real email)")
	return nil
}

func (w *Worker) handleWebhook(ctx context.Context, t *asynq.Task) error {
	w.log.Debug().Str("payload", string(t.Payload())).Msg("webhook task (noop)")
	return nil
}

// Run blocks until shutdown. Use Shutdown for graceful stop.
func (w *Worker) Run() error {
	return w.srv.Run(w.mux)
}

// Shutdown stops the worker.
func (w *Worker) Shutdown() {
	w.srv.Shutdown()
}
