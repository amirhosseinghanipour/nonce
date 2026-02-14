package domain

import (
	"time"

	"github.com/google/uuid"
)

// OrganizationID is a value object for organization identity.
type OrganizationID struct{ uuid.UUID }

// NewOrganizationID creates a new OrganizationID from uuid.
func NewOrganizationID(id uuid.UUID) OrganizationID { return OrganizationID{UUID: id} }

// String returns the canonical string form.
func (o OrganizationID) String() string { return o.UUID.String() }

// Organization is a project-scoped org (first-class entity). Users belong via organization_members.
type Organization struct {
	ID        OrganizationID
	ProjectID ProjectID
	Name      string
	CreatedAt time.Time
}

// OrganizationMember links a user to an org with a role.
type OrganizationMember struct {
	OrganizationID OrganizationID
	UserID         UserID
	Role           string
	CreatedAt      time.Time
}
