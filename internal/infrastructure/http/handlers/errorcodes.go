package handlers

// API error codes returned in JSON { "error": "...", "code": "..." } for stable client handling.
const (
	ErrCodeInvalidCredentials = "invalid_credentials"
	ErrCodeAccountLocked      = "account_locked"
	ErrCodeUnauthorized       = "unauthorized"
	ErrCodeInvalidRequest     = "invalid_request"
	ErrCodeNotFound           = "not_found"
	ErrCodeConflict           = "conflict"
	ErrCodeForbidden          = "forbidden"
	ErrCodeNotImplemented     = "not_implemented"
	ErrCodeInvalidToken       = "invalid_token"
	ErrCodeSessionRevoked     = "session_revoked"
	ErrCodeInternal           = "internal_error"
)
