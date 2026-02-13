package middleware

import (
	"net/http"
)

const adminSecretHeader = "X-Nonce-Admin-Secret"

// RequireAdminSecret returns a middleware that requires X-Nonce-Admin-Secret to match the given secret.
// If secret is empty, all requests are rejected with 401.
func RequireAdminSecret(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"admin API not configured (NONCE_ADMIN_SECRET)"}`))
				return
			}
			if r.Header.Get(adminSecretHeader) != secret {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid or missing admin secret"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
