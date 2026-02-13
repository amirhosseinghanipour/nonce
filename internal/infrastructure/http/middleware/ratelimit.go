package middleware

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/ulule/limiter/v3"
	"github.com/ulule/limiter/v3/drivers/store/memory"
	stdlib "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
)

// RateLimitConfig holds rate limit settings.
type RateLimitConfig struct {
	// Rate per IP ("100-M" = 100/min). Empty disables.
	RatePerIP string
	// Rate per project ("200-M"). Empty disables.
	RatePerProject string
}

// NewIPRateLimiter returns middleware that limits by client IP (in-memory store).
// rateFormatted: "100-M", "1000-H", "50-S".
func NewIPRateLimiter(rateFormatted string) (func(next http.Handler) http.Handler, error) {
	if rateFormatted == "" {
		return noopMiddleware, nil
	}
	rate, err := limiter.NewRateFromFormatted(rateFormatted)
	if err != nil {
		return nil, err
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	return stdlib.NewMiddleware(instance).Handler, nil
}

// NewProjectRateLimiter returns middleware that limits by project ID from context.
// Use after TenantResolver. rateFormatted: "200-M", etc.
func NewProjectRateLimiter(rateFormatted string) (func(next http.Handler) http.Handler, error) {
	if rateFormatted == "" {
		return noopMiddleware, nil
	}
	rate, err := limiter.NewRateFromFormatted(rateFormatted)
	if err != nil {
		return nil, err
	}
	store := memory.NewStore()
	instance := limiter.New(store, rate)
	return projectLimitMiddleware(instance), nil
}

func projectLimitMiddleware(instance *limiter.Limiter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			project := ProjectFromContext(r.Context())
			if project == nil {
				next.ServeHTTP(w, r)
				return
			}
			key := "project:" + project.ID.String()
			ctx, err := instance.Increment(r.Context(), key, 1)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if ctx.Reached {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":"rate limit exceeded"}`))
				return
			}
			w.Header().Set("X-RateLimit-Limit", strconv.FormatInt(ctx.Limit, 10))
			w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(ctx.Remaining, 10))
			if ctx.Reset > 0 {
				w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", ctx.Reset))
			}
			next.ServeHTTP(w, r)
		})
	}
}

func noopMiddleware(next http.Handler) http.Handler {
	return next
}
