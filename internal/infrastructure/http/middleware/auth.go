package middleware

import (
	"net/http"
	"strings"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
)

// AuthValidator validates the JWT and sets user/project in context (see AuthFromContext).
type AuthValidator struct {
	issuer ports.TokenIssuer
}

func NewAuthValidator(issuer ports.TokenIssuer) *AuthValidator {
	return &AuthValidator{issuer: issuer}
}

func (m *AuthValidator) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
			writeErrTenant(w, http.StatusUnauthorized, "unauthorized", "missing or invalid authorization")
			return
		}
		tokenString := strings.TrimPrefix(auth, "Bearer ")
		projectID, userID, orgID, role, err := m.issuer.ValidateAccessToken(tokenString)
		if err != nil {
			writeErrTenant(w, http.StatusUnauthorized, "invalid_token", "invalid token")
			return
		}
		ctx := WithAuth(r.Context(), projectID, userID, orgID, role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
