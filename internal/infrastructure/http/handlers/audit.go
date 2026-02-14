package handlers

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// AuditLog logs auth events (project_id, user_id, IP).
func AuditLog(log zerolog.Logger, r *http.Request, event string, projectID, userID string, success bool, errMsg string) {
	ev := log.Info()
	if !success {
		ev = log.Warn()
	}
	ev.
		Str("event", event).
		Str("project_id", projectID).
		Str("user_id", userID).
		Str("ip", getClientIP(r)).
		Str("request_id", middleware.GetReqID(r.Context())).
		Bool("success", success)
	if errMsg != "" {
		ev.Str("error", errMsg)
	}
	ev.Msg("auth_audit")
}

// AuditEmit logs the event and, if emitter is non-nil, sends it to the webhook endpoint.
func AuditEmit(log zerolog.Logger, r *http.Request, emitter ports.WebhookEmitter, event, projectID, userID string, success bool, errMsg string) {
	AuditLog(log, r, event, projectID, userID, success, errMsg)
	if emitter != nil {
		_ = emitter.Emit(r.Context(), ports.AuditEvent{
			Event:     event,
			ProjectID: projectID,
			UserID:    userID,
			IP:        getClientIP(r),
			Success:   success,
			Err:       errMsg,
		})
	}
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	return r.RemoteAddr
}
