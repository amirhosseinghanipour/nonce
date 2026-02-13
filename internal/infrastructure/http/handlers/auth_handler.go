package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/amirhosseinghanipour/nonce/internal/application/auth"
	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/http/middleware"
)

type AuthHandler struct {
	register        *auth.RegisterUser
	login           *auth.Login
	refresh         *auth.Refresh
	sendMagicLink   *auth.SendMagicLink
	verifyMagicLink *auth.VerifyMagicLink
	forgotPassword  *auth.ForgotPassword
	resetPassword   *auth.ResetPassword
	issueTOTP       *auth.IssueTOTP
	verifyTOTP      *auth.VerifyTOTP
	verifyMFA       *auth.VerifyMFA
	userRepo        ports.UserRepository
	validate        *validator.Validate
	log             zerolog.Logger
}

func NewAuthHandler(register *auth.RegisterUser, login *auth.Login, refresh *auth.Refresh, sendMagicLink *auth.SendMagicLink, verifyMagicLink *auth.VerifyMagicLink, forgotPassword *auth.ForgotPassword, resetPassword *auth.ResetPassword, issueTOTP *auth.IssueTOTP, verifyTOTP *auth.VerifyTOTP, verifyMFA *auth.VerifyMFA, userRepo ports.UserRepository, log zerolog.Logger) *AuthHandler {
	return &AuthHandler{
		register:        register,
		login:           login,
		refresh:         refresh,
		sendMagicLink:   sendMagicLink,
		verifyMagicLink: verifyMagicLink,
		forgotPassword:  forgotPassword,
		resetPassword:   resetPassword,
		issueTOTP:       issueTOTP,
		verifyTOTP:      verifyTOTP,
		verifyMFA:       verifyMFA,
		userRepo:        userRepo,
		validate:        validator.New(),
		log:             log,
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
		middleware.RecordAuthAttempt("signup", project.ID.String(), false)
		if err == domerrors.ErrUserExists {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("register failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "user.signup", project.ID.String(), result.User.ID.String(), true, "")
	middleware.RecordAuthAttempt("signup", project.ID.String(), true)
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
		middleware.RecordAuthAttempt("login", project.ID.String(), false)
		if err == domerrors.ErrInvalidCredentials {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("login failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "user.login", project.ID.String(), result.User.ID.String(), true, "")
	middleware.RecordAuthAttempt("login", project.ID.String(), true)
	if result.MFARequired {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"mfa_required":  true,
			"mfa_token":     result.MFAToken,
			"mfa_expires_in": result.MFAExpiresIn,
			"user": map[string]interface{}{
				"id":    result.User.ID.String(),
				"email": result.User.Email,
			},
		})
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
		middleware.RecordAuthAttempt("refresh", "", false)
		if err == domerrors.ErrInvalidToken {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("refresh failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "auth.refresh", "", "", true, "")
	middleware.RecordAuthAttempt("refresh", "", true)
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

func (h *AuthHandler) SendMagicLink(w http.ResponseWriter, r *http.Request) {
	if h.sendMagicLink == nil {
		writeErr(w, http.StatusNotImplemented, "magic link not configured")
		return
	}
	project := middleware.ProjectFromContext(r.Context())
	if project == nil {
		writeErr(w, http.StatusUnauthorized, "project required")
		return
	}
	var body struct {
		Email string `json:"email" validate:"required,email,max=254"`
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
	if email == "" {
		writeErr(w, http.StatusBadRequest, "invalid email")
		return
	}
	_, err := h.sendMagicLink.Execute(r.Context(), auth.SendMagicLinkInput{
		ProjectID: project.ID,
		Email:     email,
	})
	if err != nil {
		AuditLog(h.log, r, "auth.magic_link.send", project.ID.String(), "", false, err.Error())
		middleware.RecordAuthAttempt("magic_link_send", project.ID.String(), false)
		h.log.Error().Err(err).Msg("send magic link failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	AuditLog(h.log, r, "auth.magic_link.send", project.ID.String(), "", true, "")
	middleware.RecordAuthAttempt("magic_link_send", project.ID.String(), true)
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "if an account exists, a magic link has been sent"})
}

func (h *AuthHandler) VerifyMagicLink(w http.ResponseWriter, r *http.Request) {
	if h.verifyMagicLink == nil {
		writeErr(w, http.StatusNotImplemented, "magic link not configured")
		return
	}
	var body struct {
		Token string `json:"token" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.verifyMagicLink.Execute(r.Context(), auth.VerifyMagicLinkInput{Token: body.Token})
	if err != nil {
		if err == domerrors.ErrMagicLinkInvalid {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("verify magic link failed")
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

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	if h.forgotPassword == nil {
		writeErr(w, http.StatusNotImplemented, "password reset not configured")
		return
	}
	project := middleware.ProjectFromContext(r.Context())
	if project == nil {
		writeErr(w, http.StatusUnauthorized, "project required")
		return
	}
	var body struct {
		Email string `json:"email" validate:"required,email,max=254"`
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
	if email == "" {
		writeErr(w, http.StatusBadRequest, "invalid email")
		return
	}
	_, err := h.forgotPassword.Execute(r.Context(), auth.ForgotPasswordInput{
		ProjectID: project.ID,
		Email:     email,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("forgot password failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusAccepted)
	writeJSON(w, http.StatusAccepted, map[string]string{"message": "if an account exists, a password reset link has been sent"})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	if h.resetPassword == nil {
		writeErr(w, http.StatusNotImplemented, "password reset not configured")
		return
	}
	var body struct {
		Token       string `json:"token" validate:"required"`
		NewPassword string `json:"new_password" validate:"required,min=8,max=128"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	password := SanitizePassword(body.NewPassword)
	if password == "" {
		writeErr(w, http.StatusBadRequest, "invalid password length")
		return
	}
	_, err := h.resetPassword.Execute(r.Context(), auth.ResetPasswordInput{
		Token:       body.Token,
		NewPassword: password,
	})
	if err != nil {
		if err == domerrors.ErrPasswordResetInvalid {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("reset password failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "password has been reset"})
}

func (h *AuthHandler) TOTPSetup(w http.ResponseWriter, r *http.Request) {
	if h.issueTOTP == nil {
		writeErr(w, http.StatusNotImplemented, "totp not configured")
		return
	}
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
	pid := domain.NewProjectID(projectID)
	uid := domain.NewUserID(userID)
	user, err := h.userRepo.GetByID(r.Context(), pid, uid)
	if err != nil || user == nil {
		writeErr(w, http.StatusUnauthorized, "user not found")
		return
	}
	var body struct {
		Issuer  string `json:"issuer"`
		Account string `json:"account"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	issuer := body.Issuer
	if issuer == "" {
		issuer = "Nonce"
	}
	account := body.Account
	if account == "" {
		account = user.Email
	}
	result, err := h.issueTOTP.Execute(r.Context(), auth.IssueTOTPInput{
		UserID:    uid,
		ProjectID: pid,
		Issuer:    issuer,
		Account:   account,
	})
	if err != nil {
		h.log.Error().Err(err).Msg("totp setup failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"secret": result.Secret,
		"url":    result.URL,
	})
}

func (h *AuthHandler) TOTPVerify(w http.ResponseWriter, r *http.Request) {
	if h.verifyTOTP == nil {
		writeErr(w, http.StatusNotImplemented, "totp not configured")
		return
	}
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
	var body struct {
		Code string `json:"code" validate:"required,len=6"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = h.verifyTOTP.Execute(r.Context(), auth.VerifyTOTPInput{
		UserID:    domain.NewUserID(userID),
		ProjectID: domain.NewProjectID(projectID),
		Code:      body.Code,
	})
	if err != nil {
		if err == auth.ErrTOTPNotSetup || err == auth.ErrTOTPInvalidCode {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err == auth.ErrTOTPAlreadyVerified {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("totp verify failed")
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"message": "totp verified"})
}

func (h *AuthHandler) MFAVerify(w http.ResponseWriter, r *http.Request) {
	if h.verifyMFA == nil {
		writeErr(w, http.StatusNotImplemented, "mfa not configured")
		return
	}
	var body struct {
		MFAToken string `json:"mfa_token" validate:"required"`
		Code     string `json:"code" validate:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := h.validate.Struct(&body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	result, err := h.verifyMFA.Execute(r.Context(), auth.VerifyMFAInput{
		MFAToken: body.MFAToken,
		Code:    body.Code,
	})
	if err != nil {
		if err == auth.ErrMFATokenInvalid || err == auth.ErrTOTPInvalidCode {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		h.log.Error().Err(err).Msg("mfa verify failed")
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
