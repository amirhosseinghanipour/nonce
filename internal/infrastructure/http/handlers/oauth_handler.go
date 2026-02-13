package handlers

import (
	"net/http"
	"net/url"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/google"

	"github.com/amirhosseinghanipour/nonce/internal/application/auth"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

const oauthProjectIDKey = "nonce_project_id"

// InitOAuthProviders registers Goth providers and session store. Call once at startup.
func InitOAuthProviders(callbackBaseURL, sessionSecret string, googleClientID, googleClientSecret string) {
	if googleClientID != "" && googleClientSecret != "" {
		callbackURL := callbackBaseURL + "/auth/google/callback"
		goth.UseProviders(google.New(googleClientID, googleClientSecret, callbackURL))
	}
	if sessionSecret != "" {
		gothic.Store = sessions.NewCookieStore([]byte(sessionSecret))
	}
}

// OAuthBegin redirects to the OAuth provider. Requires tenant (project key). Provider from URL: /auth/:provider.
func OAuthBegin(oauthCallback *auth.OAuthCallback) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		project := middleware.ProjectFromContext(r.Context())
		if project == nil {
			writeErr(w, http.StatusUnauthorized, "project required")
			return
		}
		provider := chi.URLParam(r, "provider")
		if provider == "" {
			writeErr(w, http.StatusBadRequest, "provider required")
			return
		}
		if _, err := goth.GetProvider(provider); err != nil {
			writeErr(w, http.StatusBadRequest, "unknown provider")
			return
		}
		if err := gothic.StoreInSession(oauthProjectIDKey, project.ID.String(), r, w); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Gothic expects provider in query
		r2 := r.Clone(r.Context())
		q := r2.URL.Query()
		q.Set("provider", provider)
		r2.URL.RawQuery = q.Encode()
		authURL, err := gothic.GetAuthURL(w, r2)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
	}
}

// OAuthCallback handles the OAuth callback, gets/creates user, issues tokens, redirects to frontend.
func OAuthCallback(oauthCallback *auth.OAuthCallback, redirectURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provider := chi.URLParam(r, "provider")
		if provider == "" {
			writeErr(w, http.StatusBadRequest, "provider required")
			return
		}
		r2 := r.Clone(r.Context())
		q := r2.URL.Query()
		q.Set("provider", provider)
		r2.URL.RawQuery = q.Encode()
		gothUser, err := gothic.CompleteUserAuth(w, r2)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "oauth failed")
			return
		}
		projectIDStr, err := gothic.GetFromSession(oauthProjectIDKey, r)
		if err != nil || projectIDStr == "" {
			writeErr(w, http.StatusBadRequest, "missing session")
			return
		}
		parsed, err := uuid.Parse(projectIDStr)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "invalid project")
			return
		}
		projectID := domain.NewProjectID(parsed)
		result, err := oauthCallback.Execute(r.Context(), projectID, auth.OAuthUser{
			Provider:       gothUser.Provider,
			ProviderUserID: gothUser.UserID,
			Email:          gothUser.Email,
		})
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		// Redirect to frontend with tokens in query (client should move to storage and strip URL)
		u, _ := url.Parse(redirectURL)
		uq := u.Query()
		uq.Set("access_token", result.AccessToken)
		uq.Set("refresh_token", result.RefreshToken)
		uq.Set("expires_in", strconv.FormatInt(result.ExpiresIn, 10))
		u.RawQuery = uq.Encode()
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
	}
}
