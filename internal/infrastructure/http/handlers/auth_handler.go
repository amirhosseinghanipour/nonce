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
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required,min=8"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.register.Execute(r.Context(), auth.RegisterUserInput{
		ProjectID: project.ID,
		Email:     body.Email,
		Password:  body.Password,
	})
	if err != nil {
		if err == domerrors.ErrUserExists {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("register failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
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
		Email    string `json:"email" validate:"required,email"`
		Password string `json:"password" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.login.Execute(r.Context(), auth.LoginInput{
		ProjectID: project.ID,
		Email:     body.Email,
		Password:  body.Password,
	})
	if err != nil {
		if err == domerrors.ErrInvalidCredentials {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("login failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
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
		RefreshToken string `json:"refresh_token" validate:"required"`
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
		if err == domerrors.ErrInvalidToken {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("refresh failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
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
