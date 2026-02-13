package domain

import (
	"time"

	"github.com/google/uuid"
)

// ProjectID is a value object for tenant/project identity.
type ProjectID struct{ uuid.UUID }

// NewProjectID creates a new ProjectID from uuid.
func NewProjectID(id uuid.UUID) ProjectID { return ProjectID{UUID: id} }

// String returns the canonical string form.
func (p ProjectID) String() string { return p.UUID.String() }

// Project (tenant) is a single tenant.
type Project struct {
	ID          ProjectID
	Name        string
	APIKeyHash  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}
