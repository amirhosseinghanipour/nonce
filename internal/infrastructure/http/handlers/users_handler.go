package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

// UsersHandler handles /users/* (e.g. GET /users/me). Requires JWT auth.
type UsersHandler struct {
	userRepo   ports.UserRepository
	tokenStore ports.TokenStore // required for production: revokes all sessions on DeleteMe; may be nil in tests
}

// NewUsersHandler creates the handler for user resource endpoints. tokenStore is required for production (session revocation on DeleteMe); may be nil only in tests.
func NewUsersHandler(userRepo ports.UserRepository, tokenStore ports.TokenStore) *UsersHandler {
	return &UsersHandler{userRepo: userRepo, tokenStore: tokenStore}
}

// MeResponse is the JSON shape for GET /users/me (no password).
type MeResponse struct {
	ID              string                 `json:"id"`
	ProjectID       string                 `json:"project_id"`
	Email           string                 `json:"email,omitempty"` // omitted for anonymous users
	CreatedAt       string                 `json:"created_at"`
	UpdatedAt       string                 `json:"updated_at"`
	EmailVerifiedAt *string                `json:"email_verified_at,omitempty"`
	IsAnonymous     bool                   `json:"anonymous"`
	UserMetadata    map[string]interface{} `json:"user_metadata,omitempty"`
	AppMetadata     map[string]interface{} `json:"app_metadata,omitempty"`
}

// ExportMeResponse is the GDPR data export payload (GET /users/me/export). Same as MeResponse plus export metadata.
type ExportMeResponse struct {
	ExportedAt string                 `json:"exported_at"` // ISO8601
	Data       MeResponse             `json:"data"`
}

// Me returns the current user from the JWT. Requires AuthValidator middleware.
func (h *UsersHandler) Me(w http.ResponseWriter, r *http.Request) {
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
	user, err := h.userRepo.GetByID(r.Context(), domain.NewProjectID(projectID), domain.NewUserID(userID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if user == nil {
		writeErr(w, http.StatusNotFound, "", "user not found")
		return
	}
	var emailVerifiedAt *string
	if user.EmailVerifiedAt != nil {
		t := user.EmailVerifiedAt.Format("2006-01-02T15:04:05Z07:00")
		emailVerifiedAt = &t
	}
	email := user.Email
	if user.IsAnonymous {
		email = "" // anonymous users: do not expose internal placeholder email
	}
	resp := MeResponse{
		ID:              user.ID.String(),
		ProjectID:       user.ProjectID.String(),
		Email:           email,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		EmailVerifiedAt: emailVerifiedAt,
		IsAnonymous:     user.IsAnonymous,
		UserMetadata:    user.UserMetadata,
		AppMetadata:     user.AppMetadata,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// DeleteMe soft-deletes the current user (GDPR right to erasure) and revokes all their sessions. Requires JWT.
func (h *UsersHandler) DeleteMe(w http.ResponseWriter, r *http.Request) {
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
	if h.tokenStore != nil {
		_ = h.tokenStore.RevokeAllSessionsForUser(r.Context(), pid, uid, ports.RevokedReasonAdmin)
	}
	if err := h.userRepo.SoftDelete(r.Context(), pid, uid); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

const defaultListLimit = 20
const maxListLimit = 100

// List returns project-scoped users; query params limit and offset are supported. Requires JWT (project from token).
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	projectIDStr, _, _, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project id")
		return
	}
	limit := defaultListLimit
	if l := r.URL.Query().Get("limit"); l != "" {
		if n, err := strconv.Atoi(l); err == nil && n > 0 {
			limit = n
			if limit > maxListLimit {
				limit = maxListLimit
			}
		}
	}
	offset := 0
	if o := r.URL.Query().Get("offset"); o != "" {
		if n, err := strconv.Atoi(o); err == nil && n >= 0 {
			offset = n
		}
	}
	users, err := h.userRepo.List(r.Context(), domain.NewProjectID(projectID), limit, offset)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	items := make([]MeResponse, 0, len(users))
	for _, u := range users {
		var emailVerifiedAt *string
		if u.EmailVerifiedAt != nil {
			t := u.EmailVerifiedAt.Format("2006-01-02T15:04:05Z07:00")
			emailVerifiedAt = &t
		}
		email := u.Email
		if u.IsAnonymous {
			email = ""
		}
		items = append(items, MeResponse{
			ID:              u.ID.String(),
			ProjectID:       u.ProjectID.String(),
			Email:           email,
			CreatedAt:       u.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:       u.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			EmailVerifiedAt: emailVerifiedAt,
			IsAnonymous:     u.IsAnonymous,
			UserMetadata:    u.UserMetadata,
			AppMetadata:     u.AppMetadata,
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": items})
}

// UpdateMeRequest is the body for PATCH /users/me (partial update of user_metadata).
type UpdateMeRequest struct {
	UserMetadata map[string]interface{} `json:"user_metadata"`
}

// UpdateMe merges the request user_metadata into the current user's user_metadata and saves. Requires JWT.
func (h *UsersHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
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
	var body UpdateMeRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	if body.UserMetadata == nil {
		writeErr(w, http.StatusBadRequest, "", "user_metadata required")
		return
	}
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	user, err := h.userRepo.GetByID(r.Context(), pid, uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if user == nil {
		writeErr(w, http.StatusNotFound, "", "user not found")
		return
	}
	// Merge: existing keys updated, new keys added.
	merged := make(map[string]interface{})
	if user.UserMetadata != nil {
		for k, v := range user.UserMetadata {
			merged[k] = v
		}
	}
	for k, v := range body.UserMetadata {
		merged[k] = v
	}
	if err := h.userRepo.UpdateUserMetadata(r.Context(), pid, uid, merged); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	// Return updated user (re-fetch to get consistent view).
	user, _ = h.userRepo.GetByID(r.Context(), pid, uid)
	if user == nil {
		writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
		return
	}
	email := user.Email
	if user.IsAnonymous {
		email = ""
	}
	var emailVerifiedAt *string
	if user.EmailVerifiedAt != nil {
		t := user.EmailVerifiedAt.Format("2006-01-02T15:04:05Z07:00")
		emailVerifiedAt = &t
	}
	writeJSON(w, http.StatusOK, MeResponse{
		ID:              user.ID.String(),
		ProjectID:       user.ProjectID.String(),
		Email:           email,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		EmailVerifiedAt: emailVerifiedAt,
		IsAnonymous:     user.IsAnonymous,
		UserMetadata:    user.UserMetadata,
		AppMetadata:     user.AppMetadata,
	})
}

// ExportMe returns the current user's data for GDPR/right-to-data-portability. Requires JWT.
func (h *UsersHandler) ExportMe(w http.ResponseWriter, r *http.Request) {
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
	user, err := h.userRepo.GetByID(r.Context(), domain.NewProjectID(projectID), domain.NewUserID(userID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if user == nil {
		writeErr(w, http.StatusNotFound, "", "user not found")
		return
	}
	var emailVerifiedAt *string
	if user.EmailVerifiedAt != nil {
		t := user.EmailVerifiedAt.Format("2006-01-02T15:04:05Z07:00")
		emailVerifiedAt = &t
	}
	email := user.Email
	if user.IsAnonymous {
		email = ""
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z07:00")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="user-data-export.json"`)
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(ExportMeResponse{
		ExportedAt: now,
		Data: MeResponse{
			ID:              user.ID.String(),
			ProjectID:       user.ProjectID.String(),
			Email:           email,
			CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			UpdatedAt:       user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
			EmailVerifiedAt: emailVerifiedAt,
			IsAnonymous:     user.IsAnonymous,
			UserMetadata:    user.UserMetadata,
			AppMetadata:     user.AppMetadata,
		},
	})
}
