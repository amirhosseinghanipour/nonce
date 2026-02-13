package handlers

import "strings"

// Validation limits.
const (
	MaxEmailLength    = 254
	MaxPasswordLength = 128
	MaxRefreshToken   = 1024
)

// SanitizeEmail trims and lowercases email; returns empty if invalid length.
func SanitizeEmail(email string) string {
	s := strings.TrimSpace(strings.ToLower(email))
	if len(s) > MaxEmailLength {
		return ""
	}
	return s
}

// SanitizePassword trims password; returns empty if over max length.
func SanitizePassword(password string) string {
	s := strings.TrimSpace(password)
	if len(s) > MaxPasswordLength {
		return ""
	}
	return s
}

// TruncateRefreshToken truncates token to MaxRefreshToken.
func TruncateRefreshToken(tok string) string {
	if len(tok) > MaxRefreshToken {
		return tok[:MaxRefreshToken]
	}
	return tok
}
