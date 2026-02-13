package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimid "github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/handlers"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

type RouterConfig struct {
	AuthHandler       *handlers.AuthHandler
	Tenant            *middleware.TenantResolver
	Log               zerolog.Logger
	Secure            func(http.Handler) http.Handler
	IPRateLimit       func(http.Handler) http.Handler
	ProjectRateLimit  func(http.Handler) http.Handler
}

func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()
	r.Use(chimid.RequestID)
	r.Use(chimid.RealIP)
	r.Use(loggerMiddleware(cfg.Log))
	r.Use(chimid.Recoverer)
	if cfg.Secure != nil {
		r.Use(cfg.Secure)
	}
	r.Use(chimid.AllowContentType("application/json"))
	r.Use(chimid.SetHeader("Content-Type", "application/json"))
	if cfg.IPRateLimit != nil {
		r.Use(cfg.IPRateLimit)
	}

	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	r.Route("/auth", func(r chi.Router) {
		r.Use(cfg.Tenant.Handler)
		if cfg.ProjectRateLimit != nil {
			r.Use(cfg.ProjectRateLimit)
		}
		r.Post("/signup", cfg.AuthHandler.Signup)
		r.Post("/login", cfg.AuthHandler.Login)
		r.Post("/refresh", cfg.AuthHandler.Refresh)
		r.Post("/logout", cfg.AuthHandler.Logout)
	})

	return r
}

func loggerMiddleware(log zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := chimid.GetReqID(r.Context())
			log.Info().
				Str("request_id", reqID).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Msg("request")
			next.ServeHTTP(w, r)
		})
	}
}
