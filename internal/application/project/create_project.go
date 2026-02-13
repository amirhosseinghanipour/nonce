package project

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/google/uuid"
)

// CreateProjectInput is the project name.
type CreateProjectInput struct {
	Name string
}

// CreateProjectResult returns the created project and the plain API key (only time it is visible).
type CreateProjectResult struct {
	Project *domain.Project
	APIKey  string
}

// CreateProject creates a project with a generated API key; returns the plain key once.
type CreateProject struct {
	projectRepo ports.ProjectRepository
	hashKey     func(string) string
}

// NewCreateProject builds the use case.
func NewCreateProject(projectRepo ports.ProjectRepository, hashKey func(string) string) *CreateProject {
	if hashKey == nil {
		hashKey = sha256Hex
	}
	return &CreateProject{projectRepo: projectRepo, hashKey: hashKey}
}

// Execute creates the project and returns it with the plain API key.
func (uc *CreateProject) Execute(ctx context.Context, input CreateProjectInput) (*CreateProjectResult, error) {
	id := uuid.New()
	now := time.Now()
	plainKey, err := generateAPIKey()
	if err != nil {
		return nil, err
	}
	hash := uc.hashKey(plainKey)
	project := &domain.Project{
		ID:         domain.NewProjectID(id),
		Name:       input.Name,
		APIKeyHash: hash,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := uc.projectRepo.Create(ctx, project); err != nil {
		return nil, err
	}
	return &CreateProjectResult{Project: project, APIKey: plainKey}, nil
}

func generateAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "nonce_" + hex.EncodeToString(b), nil
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
