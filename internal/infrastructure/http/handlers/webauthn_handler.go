package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
	webauthnsvc "github.com/amirhosseinghanipour/nonce/internal/infrastructure/webauthn"
)

const webauthnSessionHeader = "X-WebAuthn-Session-ID"

// WebAuthnHandler handles WebAuthn registration and passkey login.
type WebAuthnHandler struct {
	svc        *webauthnsvc.Service
	issuer     ports.TokenIssuer
	tokenStore ports.TokenStore
	userRepo   ports.UserRepository
	accessExp   int64
	refreshExp  int64
	log         zerolog.Logger
}

// NewWebAuthnHandler creates a handler for WebAuthn flows.
func NewWebAuthnHandler(svc *webauthnsvc.Service, issuer ports.TokenIssuer, tokenStore ports.TokenStore, userRepo ports.UserRepository, accessExp, refreshExp int64, log zerolog.Logger) *WebAuthnHandler {
	return &WebAuthnHandler{
		svc:        svc,
		issuer:     issuer,
		tokenStore: tokenStore,
		userRepo:   userRepo,
		accessExp:  accessExp,
		refreshExp: refreshExp,
		log:        log,
	}
}

// RegisterBegin returns creation options and session_id. Requires JWT.
func (h *WebAuthnHandler) RegisterBegin(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeErr(w, http.StatusNotImplemented, "", "webauthn not configured")
		return
	}
	projectIDStr, userIDStr, _, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user id")
		return
	}
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	creationJSON, sessionID, err := h.svc.BeginRegistration(r.Context(), pid, uid)
	if err != nil {
		h.log.Error().Err(err).Msg("webauthn register begin failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	var creation map[string]interface{}
	_ = json.Unmarshal(creationJSON, &creation)
	creation["session_id"] = sessionID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(creation)
}

// RegisterFinish consumes the credential response and stores the passkey. Requires JWT; session_id in header.
func (h *WebAuthnHandler) RegisterFinish(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeErr(w, http.StatusNotImplemented, "", "webauthn not configured")
		return
	}
	projectIDStr, userIDStr, _, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	sessionID := r.Header.Get(webauthnSessionHeader)
	if sessionID == "" {
		writeErr(w, http.StatusBadRequest, "", "missing "+webauthnSessionHeader)
		return
	}
	projectID, _ := uuid.Parse(projectIDStr)
	userID, _ := uuid.Parse(userIDStr)
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	err := h.svc.FinishRegistration(r.Context(), pid, uid, sessionID, r.Body)
	if err != nil {
		if err == webauthnsvc.ErrInvalidSession {
			writeErr(w, http.StatusBadRequest, "", err.Error())
			return
		}
		h.log.Error().Err(err).Msg("webauthn register finish failed")
		writeErr(w, http.StatusBadRequest, "", "registration failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "passkey registered"})
}

// LoginBegin returns assertion options and session_id. Requires project key.
func (h *WebAuthnHandler) LoginBegin(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeErr(w, http.StatusNotImplemented, "", "webauthn not configured")
		return
	}
	project := middleware.ProjectFromContext(r.Context())
	if project == nil {
		writeErr(w, http.StatusUnauthorized, "", "project required")
		return
	}
	assertionJSON, sessionID, err := h.svc.BeginLogin(r.Context(), project.ID)
	if err != nil {
		h.log.Error().Err(err).Msg("webauthn login begin failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	var assertion map[string]interface{}
	_ = json.Unmarshal(assertionJSON, &assertion)
	assertion["session_id"] = sessionID
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(assertion)
}

// LoginFinish validates the assertion and returns access + refresh tokens. Session_id in header; body = assertion response.
func (h *WebAuthnHandler) LoginFinish(w http.ResponseWriter, r *http.Request) {
	if h.svc == nil {
		writeErr(w, http.StatusNotImplemented, "", "webauthn not configured")
		return
	}
	sessionID := r.Header.Get(webauthnSessionHeader)
	if sessionID == "" {
		writeErr(w, http.StatusBadRequest, "", "missing "+webauthnSessionHeader)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	projectID, userID, err := h.svc.FinishLogin(r.Context(), sessionID, &bufferReader{b: body})
	if err != nil {
		if err == webauthnsvc.ErrInvalidSession {
			writeErr(w, http.StatusBadRequest, "", err.Error())
			return
		}
		h.log.Error().Err(err).Msg("webauthn login finish failed")
		writeErr(w, http.StatusUnauthorized, "", "authentication failed")
		return
	}
	user, err := h.userRepo.GetByID(r.Context(), projectID, userID)
	if err != nil || user == nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	accessToken, err := h.issuer.IssueAccessToken(projectID.String(), userID.String(), h.accessExp)
	if err != nil {
		h.log.Error().Err(err).Msg("issue access token failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	refreshRaw := make([]byte, 32)
	rand.Read(refreshRaw)
	refreshToken := hex.EncodeToString(refreshRaw)
	refreshHash := refreshTokenHashForLookup(refreshToken)
	expiresAt := time.Now().Add(time.Duration(h.refreshExp) * time.Second).Unix()
	authSessionID, err := h.tokenStore.CreateSession(r.Context(), projectID, userID)
	if err != nil {
		h.log.Error().Err(err).Msg("create session failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if err := h.tokenStore.StoreRefreshToken(r.Context(), projectID, userID, authSessionID, nil, refreshHash, expiresAt); err != nil {
		h.log.Error().Err(err).Msg("store refresh token failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"expires_in":    h.accessExp,
		"user": map[string]interface{}{
			"id":    user.ID.String(),
			"email": user.Email,
		},
	})
}

type bufferReader struct{ b []byte }

func (b *bufferReader) Read(p []byte) (n int, err error) {
	if len(b.b) == 0 {
		return 0, io.EOF
	}
	n = copy(p, b.b)
	b.b = b.b[n:]
	return n, nil
}
