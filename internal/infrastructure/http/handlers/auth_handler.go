package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/auth"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

type AuthHandler struct {
	register *auth.RegisterUser
	login    *auth.Login
	refresh  *auth.Refresh
	validate *validator.Validate
	log      zerolog.Logger
}

func NewAuthHandler(register *auth.RegisterUser, login *auth.Login, refresh *auth.Refresh, log zerolog.Logger) *AuthHandler {
	return &AuthHandler{
		register: register,
		login:    login,
		refresh:  refresh,
		validate: validator.New(),
		log:      log,
	}
}

func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	project := middleware.ProjectFromContext(r.Context())
	if project == nil {
		writeErr(w, http.StatusUnauthorized, "project required")
		return
	}
	var body struct {
		Email    string `json:"email" validate:"required,email,max=254"`
		Password string `json:"password" validate:"required,min=8,max=128"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	email := SanitizeEmail(body.Email)
	password := SanitizePassword(body.Password)
	if email == "" || password == "" {
		writeErr(w, http.StatusBadRequest, "invalid email or password length")
		return
	}
	result, err := h.register.Execute(r.Context(), auth.RegisterUserInput{
		ProjectID: project.ID,
		Email:     email,
		Password:  password,
	})
	if err != nil {
		AuditLog(h.log, r, "user.signup", project.ID.String(), "", false, err.Error())
		if err == domerrors.ErrUserExists {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("register failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "user.signup", project.ID.String(), result.User.ID.String(), true, "")
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"id":         result.User.ID.String(),
		"project_id": result.User.ProjectID.String(),
		"email":      result.User.Email,
		"created_at": result.User.CreatedAt,
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	project := middleware.ProjectFromContext(r.Context())
	if project == nil {
		writeErr(w, http.StatusUnauthorized, "project required")
		return
	}
	var body struct {
		Email    string `json:"email" validate:"required,email,max=254"`
		Password string `json:"password" validate:"required,max=128"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	email := SanitizeEmail(body.Email)
	password := SanitizePassword(body.Password)
	if email == "" || password == "" {
		writeErr(w, http.StatusBadRequest, "invalid email or password length")
		return
	}
	result, err := h.login.Execute(r.Context(), auth.LoginInput{
		ProjectID: project.ID,
		Email:     email,
		Password:  password,
	})
	if err != nil {
		AuditLog(h.log, r, "user.login", project.ID.String(), "", false, err.Error())
		if err == domerrors.ErrInvalidCredentials {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("login failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "user.login", project.ID.String(), result.User.ID.String(), true, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
		"user": map[string]interface{}{
			"id":    result.User.ID.String(),
			"email": result.User.Email,
		},
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token" validate:"required,max=1024"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.refresh.Execute(r.Context(), auth.RefreshInput{RefreshToken: body.RefreshToken})
	if err != nil {
		AuditLog(h.log, r, "auth.refresh", "", "", false, err.Error())
		if err == domerrors.ErrInvalidToken {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("refresh failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "auth.refresh", "", "", true, "")
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"access_token":  result.AccessToken,
		"refresh_token": result.RefreshToken,
		"expires_in":    result.ExpiresIn,
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.RefreshToken != "" {
		// TODO: revoke refresh token in store
	}
	w.WriteHeader(http.StatusNoContent)
}
