package http

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimid "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/handlers"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

type RouterConfig struct {
	AuthHandler       *handlers.AuthHandler
	HealthHandler     *handlers.HealthHandler
	UsersHandler      *handlers.UsersHandler
	WebAuthnHandler   *handlers.WebAuthnHandler
	AdminHandler      *handlers.AdminHandler
	Tenant            *middleware.TenantResolver
	RequireJWT        func(http.Handler) http.Handler // JWT auth for /users/* etc.
	RequireAdmin      func(http.Handler) http.Handler // X-Nonce-Admin-Secret for /admin/*
	OAuthBegin        http.HandlerFunc                 // GET /auth/:provider (tenant required)
	OAuthCallback     http.HandlerFunc                 // GET /auth/:provider/callback
	Log               zerolog.Logger
	Secure            func(http.Handler) http.Handler
	IPRateLimit       func(http.Handler) http.Handler
	ProjectRateLimit  func(http.Handler) http.Handler
	Metrics           bool // expose /metrics
}

func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()
	r.Use(chimid.RequestID)
	r.Use(chimid.RealIP)
	r.Use(loggerMiddleware(cfg.Log))
	r.Use(chimid.Recoverer)
	if cfg.Metrics {
		r.Use(middleware.PrometheusMiddleware)
	}
	if cfg.Secure != nil {
		r.Use(cfg.Secure)
	}
	r.Use(chimid.AllowContentType("application/json"))
	r.Use(chimid.SetHeader("Content-Type", "application/json"))
	if cfg.IPRateLimit != nil {
		r.Use(cfg.IPRateLimit)
	}

	if cfg.HealthHandler != nil {
		r.Get("/health", cfg.HealthHandler.ServeHTTP)
	} else {
		r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
	}
	if cfg.Metrics {
		r.Handle("/metrics", promhttp.Handler())
	}

	r.Route("/auth", func(r chi.Router) {
		// Routes that do not require project key (token in body)
		r.Post("/refresh", cfg.AuthHandler.Refresh)
		r.Post("/logout", cfg.AuthHandler.Logout)
		r.Post("/magic-link/verify", cfg.AuthHandler.VerifyMagicLink)
		r.Post("/reset-password", cfg.AuthHandler.ResetPassword)
		r.Post("/verify-email", cfg.AuthHandler.VerifyEmail)
		r.Post("/mfa/verify", cfg.AuthHandler.MFAVerify)
		if cfg.WebAuthnHandler != nil {
			r.Post("/webauthn/login/finish", cfg.WebAuthnHandler.LoginFinish)
		}
		// Routes that require project key
		r.Group(func(r chi.Router) {
			r.Use(cfg.Tenant.Handler)
			if cfg.ProjectRateLimit != nil {
				r.Use(cfg.ProjectRateLimit)
			}
			r.Post("/signup", cfg.AuthHandler.Signup)
			r.Post("/login", cfg.AuthHandler.Login)
			r.Post("/anonymous", cfg.AuthHandler.Anonymous)
			r.Post("/magic-link/send", cfg.AuthHandler.SendMagicLink)
			r.Post("/forgot-password", cfg.AuthHandler.ForgotPassword)
			if cfg.WebAuthnHandler != nil {
				r.Post("/webauthn/login/begin", cfg.WebAuthnHandler.LoginBegin)
			}
			if cfg.OAuthBegin != nil {
				r.Get("/{provider}", cfg.OAuthBegin)
			}
		})
		if cfg.OAuthCallback != nil {
			r.Get("/{provider}/callback", cfg.OAuthCallback)
		}
		// Routes that require JWT (logged-in user)
		if cfg.RequireJWT != nil {
			r.Group(func(r chi.Router) {
				r.Use(cfg.RequireJWT)
				r.Post("/send-verification-email", cfg.AuthHandler.SendVerificationEmail)
				r.Post("/mfa/totp/setup", cfg.AuthHandler.TOTPSetup)
				r.Post("/mfa/totp/verify", cfg.AuthHandler.TOTPVerify)
				if cfg.WebAuthnHandler != nil {
					r.Post("/webauthn/register/begin", cfg.WebAuthnHandler.RegisterBegin)
					r.Post("/webauthn/register/finish", cfg.WebAuthnHandler.RegisterFinish)
				}
			})
		}
	})

	if cfg.UsersHandler != nil && cfg.RequireJWT != nil {
		r.Route("/users", func(r chi.Router) {
			r.Use(cfg.RequireJWT)
			r.Get("/", cfg.UsersHandler.List)
			r.Get("/me", cfg.UsersHandler.Me)
		})
	}

	if cfg.AdminHandler != nil && cfg.RequireAdmin != nil {
		r.Route("/admin", func(r chi.Router) {
			r.Use(cfg.RequireAdmin)
			r.Post("/projects", cfg.AdminHandler.CreateProject)
			r.Post("/projects/{id}/rotate-key", cfg.AdminHandler.RotateProjectKey)
		})
	}

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
