package ports

import "context"

// LoginLockoutStore tracks failed login attempts and cooldown for (project_id, email).
type LoginLockoutStore interface {
	// IsLocked returns true if the account is locked, and the remaining cooldown duration.
	IsLocked(ctx context.Context, projectID, email string) (locked bool, retryAfterSeconds int)
	// RecordFailure records a failed login; may lock the account after N failures.
	RecordFailure(ctx context.Context, projectID, email string)
	// RecordSuccess clears failure count for the account (call on successful login).
	RecordSuccess(ctx context.Context, projectID, email string)
}
