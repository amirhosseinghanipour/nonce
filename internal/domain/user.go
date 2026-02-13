package domain

import (
	"time"

	"github.com/google/uuid"
)

// UserID is a value object for user identity.
type UserID struct{ uuid.UUID }

// NewUserID creates a new UserID from uuid.
func NewUserID(id uuid.UUID) UserID { return UserID{UUID: id} }

// String returns the canonical string form.
func (u UserID) String() string { return u.UUID.String() }

// User is a project-scoped user.
type User struct {
	ID              UserID
	ProjectID       ProjectID
	Email           string
	PasswordHash    string
	CreatedAt       time.Time
	UpdatedAt       time.Time
	EmailVerifiedAt *time.Time
}
