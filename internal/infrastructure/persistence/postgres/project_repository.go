package postgres

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/jackc/pgx/v5"
)

type ProjectRepository struct {
	q *db.Queries
}

func NewProjectRepository(q *db.Queries) *ProjectRepository {
	return &ProjectRepository{q: q}
}

func (r *ProjectRepository) GetByID(ctx context.Context, projectID domain.ProjectID) (*domain.Project, error) {
	p, err := r.q.GetProjectByID(ctx, projectID.UUID)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbProjectToDomain(p), nil
}

func (r *ProjectRepository) GetByAPIKeyHash(ctx context.Context, apiKeyHash string) (*domain.Project, error) {
	p, err := r.q.GetProjectByAPIKeyHash(ctx, apiKeyHash)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return dbProjectToDomain(p), nil
}

func dbProjectToDomain(p db.Project) *domain.Project {
	return &domain.Project{
		ID:         domain.NewProjectID(p.ID),
		Name:       p.Name,
		APIKeyHash: p.ApiKeyHash,
		CreatedAt:  p.CreatedAt,
		UpdatedAt:  p.UpdatedAt,
	}
}

// Ensure ProjectRepository implements ports.ProjectRepository.
var _ ports.ProjectRepository = (*ProjectRepository)(nil)
