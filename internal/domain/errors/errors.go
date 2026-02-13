package errors

import "errors"

// Sentinel errors for handlers to map to HTTP status.
var (
	ErrUserExists         = errors.New("user already exists for this project")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrTenantNotFound     = errors.New("project not found or invalid API key")
	ErrUserNotFound       = errors.New("user not found")
	ErrInvalidToken       = errors.New("invalid or expired refresh token")
)
