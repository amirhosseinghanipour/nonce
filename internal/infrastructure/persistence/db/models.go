package db

import (
	"time"

	"github.com/google/uuid"
)

type Project struct {
	ID         uuid.UUID
	Name       string
	ApiKeyHash string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

type User struct {
	ID           uuid.UUID
	ProjectID    uuid.UUID
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type RefreshToken struct {
	ID        uuid.UUID
	ProjectID uuid.UUID
	UserID    uuid.UUID
	TokenHash string
	ExpiresAt time.Time
	CreatedAt time.Time
}
