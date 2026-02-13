package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

// UsersHandler handles /users/* (e.g. GET /users/me). Requires JWT auth.
type UsersHandler struct {
	userRepo ports.UserRepository
}

// NewUsersHandler creates a handler for user resource endpoints.
func NewUsersHandler(userRepo ports.UserRepository) *UsersHandler {
	return &UsersHandler{userRepo: userRepo}
}

// MeResponse is the JSON shape for GET /users/me (no password).
type MeResponse struct {
	ID              string  `json:"id"`
	ProjectID       string  `json:"project_id"`
	Email           string  `json:"email,omitempty"` // omitted for anonymous users
	CreatedAt       string  `json:"created_at"`
	UpdatedAt       string  `json:"updated_at"`
	EmailVerifiedAt *string `json:"email_verified_at,omitempty"`
	IsAnonymous     bool    `json:"anonymous"`
}

// Me returns the current user from the JWT. Requires AuthValidator middleware.
func (h *UsersHandler) Me(w http.ResponseWriter, r *http.Request) {
	projectIDStr, userIDStr := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid project id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid user id")
		return
	}
	user, err := h.userRepo.GetByID(r.Context(), domain.NewProjectID(projectID), domain.NewUserID(userID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if user == nil {
		writeErr(w, http.StatusNotFound, "user not found")
		return
	}
	var emailVerifiedAt *string
	if user.EmailVerifiedAt != nil {
		t := user.EmailVerifiedAt.Format("2006-01-02T15:04:05Z07:00")
		emailVerifiedAt = &t
	}
	email := user.Email
	if user.IsAnonymous {
		email = "" // don't expose placeholder email
	}
	resp := MeResponse{
		ID:              user.ID.String(),
		ProjectID:       user.ProjectID.String(),
		Email:           email,
		CreatedAt:       user.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		UpdatedAt:       user.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"),
		EmailVerifiedAt: emailVerifiedAt,
		IsAnonymous:     user.IsAnonymous,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

const defaultListLimit = 20
const maxListLimit = 100

// List returns project-scoped users with optional limit/offset. Requires JWT (project from token).
func (h *UsersHandler) List(w http.ResponseWriter, r *http.Request) {
	projectIDStr, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid project id")
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
		writeErr(w, http.StatusInternalServerError, "internal error")
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
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"users": items})
}
