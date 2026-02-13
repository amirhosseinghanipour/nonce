package middleware

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "nonce_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path", "status"},
	)
	authAttempts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nonce_auth_attempts_total",
			Help: "Total auth attempts by outcome and project",
		},
		[]string{"event", "project_id", "success"},
	)
)

// PrometheusMiddleware records request duration.
func PrometheusMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		start := time.Now()
		next.ServeHTTP(ww, r)
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(ww.Status())
		path := r.URL.Path
		if path == "" {
			path = "/"
		}
		httpRequestDuration.WithLabelValues(r.Method, path, status).Observe(duration)
	})
}

// RecordAuthAttempt records an auth event for Prometheus.
func RecordAuthAttempt(event, projectID string, success bool) {
	authAttempts.WithLabelValues(event, projectID, strconv.FormatBool(success)).Inc()
}
