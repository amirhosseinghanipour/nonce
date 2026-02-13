package queue

import (
	"context"
	"encoding/json"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/hibiken/asynq"
	"github.com/rs/zerolog"
)

const (
	TypeSendMagicLink          = "email:magic_link"
	TypeSendPasswordReset      = "email:password_reset"
	TypeSendEmailVerification  = "email:email_verification"
	TypeWebhook                = "webhook:emit"
)

type TaskEnqueuer struct {
	client *asynq.Client
	log    zerolog.Logger
}

func NewAsynqEnqueuer(redisOpt asynq.RedisClientOpt, log zerolog.Logger) (*TaskEnqueuer, error) {
	client := asynq.NewClient(redisOpt)
	return &TaskEnqueuer{client: client, log: log}, nil
}

func (q *TaskEnqueuer) Close() error {
	return q.client.Close()
}

func (q *TaskEnqueuer) EnqueueSendMagicLink(ctx context.Context, projectID, email, linkURL string) error {
	payload, _ := json.Marshal(map[string]string{
		"project_id": projectID,
		"email":      email,
		"link_url":   linkURL,
	})
	task := asynq.NewTask(TypeSendMagicLink, payload)
	_, err := q.client.EnqueueContext(ctx, task)
	if err != nil {
		q.log.Warn().Err(err).Str("email", email).Msg("enqueue magic link email failed")
		return err
	}
	return nil
}

func (q *TaskEnqueuer) EnqueueSendPasswordReset(ctx context.Context, projectID, email, resetURL string) error {
	payload, _ := json.Marshal(map[string]string{
		"project_id": projectID,
		"email":      email,
		"reset_url": resetURL,
	})
	task := asynq.NewTask(TypeSendPasswordReset, payload)
	_, err := q.client.EnqueueContext(ctx, task)
	if err != nil {
		q.log.Warn().Err(err).Str("email", email).Msg("enqueue password reset email failed")
		return err
	}
	return nil
}

func (q *TaskEnqueuer) EnqueueSendEmailVerification(ctx context.Context, projectID, email, verifyURL string) error {
	payload, _ := json.Marshal(map[string]string{
		"project_id": projectID,
		"email":      email,
		"verify_url": verifyURL,
	})
	task := asynq.NewTask(TypeSendEmailVerification, payload)
	_, err := q.client.EnqueueContext(ctx, task)
	if err != nil {
		q.log.Warn().Err(err).Str("email", email).Msg("enqueue email verification failed")
		return err
	}
	return nil
}

func (q *TaskEnqueuer) EnqueueWebhook(ctx context.Context, event string, payload interface{}) error {
	body, _ := json.Marshal(struct {
		Event   string      `json:"event"`
		Payload interface{} `json:"payload"`
	}{Event: event, Payload: payload})
	task := asynq.NewTask(TypeWebhook, body)
	_, err := q.client.EnqueueContext(ctx, task)
	if err != nil {
		q.log.Warn().Err(err).Str("event", event).Msg("enqueue webhook failed")
		return err
	}
	return nil
}

var _ ports.TaskEnqueuer = (*TaskEnqueuer)(nil)
