package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

// HealthHandler serves /health with DB and optional Redis checks.
type HealthHandler struct {
	pool *pgxpool.Pool
	redis *redis.Client
}

// NewHealthHandler creates a health handler (redis optional).
func NewHealthHandler(pool *pgxpool.Pool, redisClient *redis.Client) *HealthHandler {
	return &HealthHandler{pool: pool, redis: redisClient}
}

type healthResponse struct {
	Status  string            `json:"status"`
	Checks  map[string]string `json:"checks,omitempty"`
	Message string            `json:"message,omitempty"`
}

func (h *HealthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]string)
	allOK := true

	if err := h.pool.Ping(ctx); err != nil {
		checks["database"] = "down: " + err.Error()
		allOK = false
	} else {
		checks["database"] = "ok"
	}

	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = "down: " + err.Error()
			allOK = false
		} else {
			checks["redis"] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if !allOK {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(healthResponse{
			Status:  "unhealthy",
			Checks:  checks,
			Message: "one or more checks failed",
		})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status: "ok",
		Checks: checks,
	})
}
