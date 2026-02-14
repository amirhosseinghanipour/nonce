package postgres

import (
	"context"
	"time"

	"github.com/amirhosseinghanipour/nonce/internal/application/ports"
	"github.com/amirhosseinghanipour/nonce/internal/domain"
	"github.com/amirhosseinghanipour/nonce/internal/infrastructure/persistence/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type OrganizationRepository struct {
	q   *db.Queries
	pool *pgxpool.Pool
}

func NewOrganizationRepository(q *db.Queries, pool *pgxpool.Pool) *OrganizationRepository {
	return &OrganizationRepository{q: q, pool: pool}
}

func (r *OrganizationRepository) Create(ctx context.Context, org *domain.Organization) error {
	if org.ID.UUID == (uuid.UUID{}) {
		org.ID = domain.NewOrganizationID(uuid.New())
	}
	if org.CreatedAt.IsZero() {
		org.CreatedAt = time.Now()
	}
	_, err := r.q.CreateOrganization(ctx, db.CreateOrganizationParams{
		ID:        org.ID.UUID,
		ProjectID: org.ProjectID.UUID,
		Name:      org.Name,
		CreatedAt: org.CreatedAt,
	})
	return err
}

func (r *OrganizationRepository) GetByID(ctx context.Context, projectID domain.ProjectID, orgID domain.OrganizationID) (*domain.Organization, error) {
	o, err := r.q.GetOrganizationByID(ctx, db.GetOrganizationByIDParams{
		ID:        orgID.UUID,
		ProjectID: projectID.UUID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &domain.Organization{
		ID:        domain.NewOrganizationID(o.ID),
		ProjectID: domain.NewProjectID(o.ProjectID),
		Name:      o.Name,
		CreatedAt: o.CreatedAt,
	}, nil
}

func (r *OrganizationRepository) ListByProject(ctx context.Context, projectID domain.ProjectID, limit, offset int) ([]*domain.Organization, error) {
	list, err := r.q.ListOrganizationsByProjectID(ctx, db.ListOrganizationsByProjectIDParams{
		ProjectID: projectID.UUID,
		Limit:     int32(limit),
		Offset:    int32(offset),
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Organization, 0, len(list))
	for _, o := range list {
		out = append(out, &domain.Organization{
			ID:        domain.NewOrganizationID(o.ID),
			ProjectID: domain.NewProjectID(o.ProjectID),
			Name:      o.Name,
			CreatedAt: o.CreatedAt,
		})
	}
	return out, nil
}

func (r *OrganizationRepository) ListForUser(ctx context.Context, projectID domain.ProjectID, userID domain.UserID) ([]*domain.Organization, error) {
	list, err := r.q.ListOrganizationsForUser(ctx, db.ListOrganizationsForUserParams{
		ProjectID: projectID.UUID,
		UserID:    userID.UUID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Organization, 0, len(list))
	for _, o := range list {
		out = append(out, &domain.Organization{
			ID:        domain.NewOrganizationID(o.ID),
			ProjectID: domain.NewProjectID(o.ProjectID),
			Name:      o.Name,
			CreatedAt: o.CreatedAt,
		})
	}
	return out, nil
}

func (r *OrganizationRepository) UpdateName(ctx context.Context, projectID domain.ProjectID, orgID domain.OrganizationID, name string) error {
	return r.q.UpdateOrganizationName(ctx, db.UpdateOrganizationNameParams{
		Name:      name,
		ID:        orgID.UUID,
		ProjectID: projectID.UUID,
	})
}

func (r *OrganizationRepository) AddMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID, role string) error {
	_, err := r.q.AddOrganizationMember(ctx, db.AddOrganizationMemberParams{
		OrganizationID: orgID.UUID,
		UserID:         userID.UUID,
		Role:           role,
		CreatedAt:      time.Now(),
	})
	return err
}

func (r *OrganizationRepository) RemoveMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) error {
	return r.q.RemoveOrganizationMember(ctx, db.RemoveOrganizationMemberParams{
		OrganizationID: orgID.UUID,
		UserID:         userID.UUID,
	})
}

func (r *OrganizationRepository) GetMember(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) (*domain.OrganizationMember, error) {
	m, err := r.q.GetOrganizationMember(ctx, db.GetOrganizationMemberParams{
		OrganizationID: orgID.UUID,
		UserID:         userID.UUID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &domain.OrganizationMember{
		OrganizationID: domain.NewOrganizationID(m.OrganizationID),
		UserID:         domain.NewUserID(m.UserID),
		Role:           m.Role,
		CreatedAt:      m.CreatedAt,
	}, nil
}

func (r *OrganizationRepository) GetUserRole(ctx context.Context, orgID domain.OrganizationID, userID domain.UserID) (string, error) {
	role, err := r.q.GetUserRoleInOrganization(ctx, db.GetUserRoleInOrganizationParams{
		OrganizationID: orgID.UUID,
		UserID:         userID.UUID,
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return role, nil
}

func (r *OrganizationRepository) ListMembers(ctx context.Context, orgID domain.OrganizationID) ([]*domain.OrganizationMember, error) {
	list, err := r.q.ListOrganizationMembers(ctx, orgID.UUID)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.OrganizationMember, 0, len(list))
	for _, m := range list {
		out = append(out, &domain.OrganizationMember{
			OrganizationID: domain.NewOrganizationID(m.OrganizationID),
			UserID:         domain.NewUserID(m.UserID),
			Role:           m.Role,
			CreatedAt:      m.CreatedAt,
		})
	}
	return out, nil
}

var _ ports.OrganizationRepository = (*OrganizationRepository)(nil)
