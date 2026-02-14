package middleware

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

// HashAPIKeyFunc hashes an API key for storage/lookup (SHA256).
type HashAPIKeyFunc func(string) string

// SHA256HashAPIKey returns a function that SHA256-hashes the key (hex).
func SHA256HashAPIKey() HashAPIKeyFunc {
	return func(key string) string {
		h := sha256.Sum256([]byte(key))
		return hex.EncodeToString(h[:])
	}
}

// TenantResolver validates the project API key (X-Nonce-Project-Key or Authorization: Bearer <key>)
// and sets the project in context.
type TenantResolver struct {
	projects   ports.ProjectRepository
	hashAPIKey HashAPIKeyFunc
}

func NewTenantResolver(projects ports.ProjectRepository, hashAPIKey HashAPIKeyFunc) *TenantResolver {
	return &TenantResolver{projects: projects, hashAPIKey: hashAPIKey}
}

func (m *TenantResolver) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Nonce-Project-Key")
		if key == "" {
			if auth := r.Header.Get("Authorization"); len(auth) >= 7 && auth[:7] == "Bearer " {
				key = auth[7:]
			}
		}
		if key == "" {
			writeErrTenant(w, http.StatusUnauthorized, "unauthorized", "missing project key")
			return
		}
		hash := m.hashAPIKey(key)
		project, err := m.projects.GetByAPIKeyHash(r.Context(), hash)
		if err != nil {
			writeErrTenant(w, http.StatusInternalServerError, "internal_error", "internal error")
			return
		}
		if project == nil {
			writeErrTenant(w, http.StatusUnauthorized, "unauthorized", string(domerrors.ErrTenantNotFound.Error()))
			return
		}
		ctx := WithProject(r.Context(), project)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func writeErrTenant(w http.ResponseWriter, code int, errCode, message string) {
	if errCode == "" {
		errCode = "internal_error"
		if code == http.StatusUnauthorized {
			errCode = "unauthorized"
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": errCode})
}
