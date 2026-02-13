package project

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	domerrors "github.com/amirhosseinghanipour/nonce/internal/domain/errors"
)

// RotateProjectKeyInput is the project ID to rotate.
type RotateProjectKeyInput struct {
	ProjectID domain.ProjectID
}

// RotateProjectKeyResult returns the new plain API key (only time it is visible).
type RotateProjectKeyResult struct {
	APIKey string
}

// RotateProjectKey generates a new API key for the project and updates storage.
type RotateProjectKey struct {
	projectRepo ports.ProjectRepository
	hashKey     func(string) string
}

// NewRotateProjectKey builds the use case.
func NewRotateProjectKey(projectRepo ports.ProjectRepository, hashKey func(string) string) *RotateProjectKey {
	if hashKey == nil {
		hashKey = sha256Hex
	}
	return &RotateProjectKey{projectRepo: projectRepo, hashKey: hashKey}
}

// Execute rotates the key and returns the new plain key.
func (uc *RotateProjectKey) Execute(ctx context.Context, input RotateProjectKeyInput) (*RotateProjectKeyResult, error) {
	project, err := uc.projectRepo.GetByID(ctx, input.ProjectID)
	if err != nil {
		return nil, err
	}
	if project == nil {
		return nil, domerrors.ErrProjectNotFound
	}
	plainKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	hash := uc.hashKey(plainKey)
	if err := uc.projectRepo.UpdateAPIKeyHash(ctx, input.ProjectID, hash); err != nil {
		return nil, err
	}
	return &RotateProjectKeyResult{APIKey: plainKey}, nil
}
