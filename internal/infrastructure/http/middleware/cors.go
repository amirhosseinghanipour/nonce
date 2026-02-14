package middleware

import (
	"net/http"
	"strings"
)

// CORS returns a middleware that sets Access-Control-* headers and handles OPTIONS preflight.
// When allowedOrigins is empty, CORS is disabled (middleware passes through without adding headers).
func CORS(allowedOrigins, allowedMethods, allowedHeaders []string) func(next http.Handler) http.Handler {
	originsSet := make(map[string]bool)
	for _, o := range allowedOrigins {
		originsSet[strings.TrimSpace(o)] = true
	}
	methods := strings.Join(allowedMethods, ", ")
	headers := strings.Join(allowedHeaders, ", ")
	if methods == "" {
		methods = "GET, POST, PATCH, DELETE, OPTIONS"
	}
	if headers == "" {
		headers = "Authorization, Content-Type, X-Nonce-Project-Key, X-WebAuthn-Session-ID"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(originsSet) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			origin := r.Header.Get("Origin")
			if origin != "" && originsSet[origin] {
				w.Header().Set("Access-Control-Allow-Origin", origin)
			}
			w.Header().Set("Access-Control-Allow-Methods", methods)
			w.Header().Set("Access-Control-Allow-Headers", headers)
			w.Header().Set("Access-Control-Max-Age", "86400")
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
