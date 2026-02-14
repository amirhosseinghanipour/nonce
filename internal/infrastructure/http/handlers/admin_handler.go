package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/application/project"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

// AdminHandler handles /admin/* (create project, rotate key, set app_metadata, list/revoke sessions). Requires X-Nonce-Admin-Secret.
type AdminHandler struct {
	createProject    *project.CreateProject
	rotateProjectKey *project.RotateProjectKey
	userRepo         ports.UserRepository
	tokenStore       ports.TokenStore
	validate         *validator.Validate
	log              zerolog.Logger
}

// NewAdminHandler creates the admin handler.
func NewAdminHandler(createProject *project.CreateProject, rotateProjectKey *project.RotateProjectKey, userRepo ports.UserRepository, tokenStore ports.TokenStore, log zerolog.Logger) *AdminHandler {
	return &AdminHandler{
		createProject:    createProject,
		rotateProjectKey: rotateProjectKey,
		userRepo:         userRepo,
		tokenStore:       tokenStore,
		validate:         validator.New(),
		log:              log,
	}
}

// CreateProject handles POST /admin/projects. Body: { "name": "..." }. Returns { "id", "name", "api_key" }.
func (h *AdminHandler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name" validate:"required,max=255"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", err.Error())
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" {
		writeErr(w, http.StatusBadRequest, "", "name is required")
		return
	}
	result, err := h.createProject.Execute(r.Context(), project.CreateProjectInput{Name: name})
	if err != nil {
		h.log.Error().Err(err).Msg("create project failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":       result.Project.ID.String(),
		"name":     result.Project.Name,
		"api_key": result.APIKey,
	})
}

// RotateProjectKey handles POST /admin/projects/:id/rotate-key. Returns { "api_key": "..." }.
func (h *AdminHandler) RotateProjectKey(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if idStr == "" {
		writeErr(w, http.StatusBadRequest, "", "project id required")
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project id")
		return
	}
	result, err := h.rotateProjectKey.Execute(r.Context(), project.RotateProjectKeyInput{
		ProjectID: domain.NewProjectID(id),
	})
	if err != nil {
		if err == domerrors.ErrProjectNotFound {
			writeErr(w, http.StatusNotFound, "", err.Error())
			return
		}
		h.log.Error().Err(err).Msg("rotate project key failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"api_key": result.APIKey})
}

// SetUserAppMetadata handles PATCH /admin/projects/:project_id/users/:user_id/app-metadata. Body: { "app_metadata": { ... } }.
func (h *AdminHandler) SetUserAppMetadata(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "project_id")
	userIDStr := chi.URLParam(r, "user_id")
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "project_id and user_id required")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user_id")
		return
	}
	var body struct {
		AppMetadata map[string]interface{} `json:"app_metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	if body.AppMetadata == nil {
		writeErr(w, http.StatusBadRequest, "", "app_metadata required")
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
	if err := h.userRepo.UpdateAppMetadata(r.Context(), pid, uid, body.AppMetadata); err != nil {
		h.log.Error().Err(err).Msg("update app_metadata failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "app_metadata updated"})
}

// ListUserSessions handles GET /admin/projects/:project_id/users/:user_id/sessions. Returns list of sessions for the user.
func (h *AdminHandler) ListUserSessions(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "project_id")
	userIDStr := chi.URLParam(r, "user_id")
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "project_id and user_id required")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user_id")
		return
	}
	if h.tokenStore == nil {
		writeErr(w, http.StatusNotImplemented, "", "session management is disabled")
		return
	}
	sessions, err := h.tokenStore.ListSessionsForUser(r.Context(), domain.NewProjectID(projectID), domain.NewUserID(userID))
	if err != nil {
		h.log.Error().Err(err).Msg("list sessions failed")
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	items := make([]map[string]interface{}, 0, len(sessions))
	for _, s := range sessions {
		item := map[string]interface{}{
			"id":         s.ID,
			"created_at": s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		}
		if s.RevokedAt != nil {
			item["revoked_at"] = s.RevokedAt.Format("2006-01-02T15:04:05Z07:00")
		}
		if s.RevokedReason != "" {
			item["revoked_reason"] = s.RevokedReason
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"sessions": items})
}

// RevokeUserSessions handles POST /admin/projects/:project_id/users/:user_id/sessions/revoke. Body: { "session_id": "<uuid>" } to revoke one session, or omit to revoke all sessions for the user.
func (h *AdminHandler) RevokeUserSessions(w http.ResponseWriter, r *http.Request) {
	projectIDStr := chi.URLParam(r, "project_id")
	userIDStr := chi.URLParam(r, "user_id")
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "project_id and user_id required")
		return
	}
	projectID, err := uuid.Parse(projectIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid project_id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user_id")
		return
	}
	if h.tokenStore == nil {
		writeErr(w, http.StatusNotImplemented, "", "session management is disabled")
		return
	}
	var body struct {
		SessionID string `json:"session_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	if body.SessionID != "" {
		if err := h.tokenStore.RevokeSession(r.Context(), body.SessionID, ports.RevokedReasonAdmin); err != nil {
			h.log.Error().Err(err).Msg("revoke session failed")
			writeErr(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	} else {
		if err := h.tokenStore.RevokeAllSessionsForUser(r.Context(), pid, uid, ports.RevokedReasonAdmin); err != nil {
			h.log.Error().Err(err).Msg("revoke all sessions failed")
			writeErr(w, http.StatusInternalServerError, "", "internal error")
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
