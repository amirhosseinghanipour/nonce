package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

// requireOrgRole ensures the current user is a member of the org and has one of the allowed roles (e.g. "owner", "admin").
// Returns false and writes 403 if not; the handler should return when false.
func requireOrgRole(w http.ResponseWriter, r *http.Request, orgRepo ports.OrganizationRepository, oid domain.OrganizationID, allowedRoles ...string) bool {
	_, userIDStr, _, _ := middleware.AuthFromContext(r.Context())
	if userIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return false
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user id")
		return false
	}
	member, err := orgRepo.GetMember(r.Context(), oid, domain.NewUserID(userID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return false
	}
	if member == nil {
		writeErr(w, http.StatusForbidden, "", "not a member of this organization")
		return false
	}
	role := strings.ToLower(strings.TrimSpace(member.Role))
	for _, allowed := range allowedRoles {
		if role == strings.ToLower(strings.TrimSpace(allowed)) {
			return true
		}
	}
	writeErr(w, http.StatusForbidden, "", "forbidden: requires owner or admin role")
	return false
}

// OrganizationsHandler handles /organizations/* (org-first model). Requires JWT.
type OrganizationsHandler struct {
	orgRepo ports.OrganizationRepository
}

// NewOrganizationsHandler creates a handler for organization endpoints.
func NewOrganizationsHandler(orgRepo ports.OrganizationRepository) *OrganizationsHandler {
	return &OrganizationsHandler{orgRepo: orgRepo}
}

// OrgResponse is the JSON shape for an organization (no internal fields).
type OrgResponse struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// MemberResponse is the JSON shape for an organization member.
type MemberResponse struct {
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
	CreatedAt string `json:"created_at"`
}

// List returns organizations the current user is a member of.
func (h *OrganizationsHandler) List(w http.ResponseWriter, r *http.Request) {
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
	orgs, err := h.orgRepo.ListForUser(r.Context(), domain.NewProjectID(projectID), domain.NewUserID(userID))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	items := make([]OrgResponse, 0, len(orgs))
	for _, o := range orgs {
		items = append(items, OrgResponse{
			ID:        o.ID.String(),
			ProjectID: o.ProjectID.String(),
			Name:      o.Name,
			CreatedAt: o.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"organizations": items})
}

// Create creates a new organization and adds the creator as first member with role "owner".
func (h *OrganizationsHandler) Create(w http.ResponseWriter, r *http.Request) {
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
	var body struct {
		Name string `json:"name" validate:"required,max=255"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	if body.Name == "" {
		writeErr(w, http.StatusBadRequest, "", "name required")
		return
	}
	org := &domain.Organization{
		ProjectID: domain.NewProjectID(projectID),
		Name:      body.Name,
	}
	if err := h.orgRepo.Create(r.Context(), org); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	// Add creator as first member with role "owner" (or "admin" - use a constant).
	if err := h.orgRepo.AddMember(r.Context(), org.ID, domain.NewUserID(userID), "owner"); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, OrgResponse{
		ID:        org.ID.String(),
		ProjectID: org.ProjectID.String(),
		Name:      org.Name,
		CreatedAt: org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// Get returns one organization by ID. User must be a member.
func (h *OrganizationsHandler) Get(w http.ResponseWriter, r *http.Request) {
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
	orgIDStr := chi.URLParam(r, "id")
	if orgIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "organization id required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid organization id")
		return
	}
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user id")
		return
	}
	pid := domain.NewProjectID(projectID)
	oid := domain.NewOrganizationID(orgID)
	uid := domain.NewUserID(userID)
	// Ensure user is a member.
	member, err := h.orgRepo.GetMember(r.Context(), oid, uid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	if member == nil {
		writeErr(w, http.StatusForbidden, "", "not a member of this organization")
		return
	}
	org, err := h.orgRepo.GetByID(r.Context(), pid, oid)
	if err != nil || org == nil {
		writeErr(w, http.StatusNotFound, "", "organization not found")
		return
	}
	writeJSON(w, http.StatusOK, OrgResponse{
		ID:        org.ID.String(),
		ProjectID: org.ProjectID.String(),
		Name:      org.Name,
		CreatedAt: org.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
	})
}

// UpdateName updates an organization's name. Caller must be owner or admin.
func (h *OrganizationsHandler) UpdateName(w http.ResponseWriter, r *http.Request) {
	projectIDStr, _, _, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	projectID, _ := uuid.Parse(projectIDStr)
	orgIDStr := chi.URLParam(r, "id")
	if orgIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "organization id required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid organization id")
		return
	}
	pid := domain.NewProjectID(projectID)
	oid := domain.NewOrganizationID(orgID)
	if !requireOrgRole(w, r, h.orgRepo, oid, "owner", "admin") {
		return
	}
	var body struct {
		Name string `json:"name" validate:"required,max=255"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Name == "" {
		writeErr(w, http.StatusBadRequest, "", "name required")
		return
	}
	if err := h.orgRepo.UpdateName(r.Context(), pid, oid, body.Name); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "updated"})
}

// ListMembers returns members of an organization.
func (h *OrganizationsHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	projectIDStr, userIDStr, _, _ := middleware.AuthFromContext(r.Context())
	if projectIDStr == "" || userIDStr == "" {
		writeErr(w, http.StatusUnauthorized, "", "unauthorized")
		return
	}
	userID, _ := uuid.Parse(userIDStr)
	orgIDStr := chi.URLParam(r, "id")
	if orgIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "organization id required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid organization id")
		return
	}
	oid := domain.NewOrganizationID(orgID)
	uid := domain.NewUserID(userID)
	member, err := h.orgRepo.GetMember(r.Context(), oid, uid)
	if err != nil || member == nil {
		writeErr(w, http.StatusForbidden, "", "not a member of this organization")
		return
	}
	members, err := h.orgRepo.ListMembers(r.Context(), oid)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	items := make([]MemberResponse, 0, len(members))
	for _, m := range members {
		items = append(items, MemberResponse{
			UserID:    m.UserID.String(),
			Role:      m.Role,
			CreatedAt: m.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"members": items})
}

// AddMember adds a user to an organization with a role. Caller must be owner or admin.
func (h *OrganizationsHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	orgIDStr := chi.URLParam(r, "id")
	if orgIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "organization id required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid organization id")
		return
	}
	oid := domain.NewOrganizationID(orgID)
	if !requireOrgRole(w, r, h.orgRepo, oid, "owner", "admin") {
		return
	}
	var body struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid body")
		return
	}
	if body.UserID == "" || body.Role == "" {
		writeErr(w, http.StatusBadRequest, "", "user_id and role required")
		return
	}
	memberUserID, err := uuid.Parse(body.UserID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user_id")
		return
	}
	if err := h.orgRepo.AddMember(r.Context(), oid, domain.NewUserID(memberUserID), body.Role); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"message": "member added"})
}

// RemoveMember removes a user from an organization. Caller must be owner or admin.
func (h *OrganizationsHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	orgIDStr := chi.URLParam(r, "id")
	memberUserIDStr := chi.URLParam(r, "user_id")
	if orgIDStr == "" || memberUserIDStr == "" {
		writeErr(w, http.StatusBadRequest, "", "organization id and user_id required")
		return
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid organization id")
		return
	}
	memberUserID, err := uuid.Parse(memberUserIDStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "", "invalid user_id")
		return
	}
	oid := domain.NewOrganizationID(orgID)
	if !requireOrgRole(w, r, h.orgRepo, oid, "owner", "admin") {
		return
	}
	if err := h.orgRepo.RemoveMember(r.Context(), oid, domain.NewUserID(memberUserID)); err != nil {
		writeErr(w, http.StatusInternalServerError, "", "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
