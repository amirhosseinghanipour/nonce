package middleware

import (
	"net/http"

	"github.com/unrolled/secure"
)

// SecureOptions returns secure.Options for security headers.
func SecureOptions(isDevelopment bool) secure.Options {
	return secure.Options{
		IsDevelopment:         isDevelopment,
		ContentTypeNosniff:    true,
		FrameDeny:             true,
		BrowserXssFilter:      true,
		ContentSecurityPolicy: "default-src 'self'",
		ReferrerPolicy:        "strict-origin-when-cross-origin",
	}
}

// NewSecure returns a middleware that adds security headers.
func NewSecure(opts secure.Options) func(next http.Handler) http.Handler {
	s := secure.New(opts)
	return s.Handler
}
