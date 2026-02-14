package middleware

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

type contextKey string

const (
	projectContextKey contextKey = "project"
	authProjectIDKey  contextKey = "auth_project_id"
	authUserIDKey     contextKey = "auth_user_id"
	authOrgIDKey     contextKey = "auth_org_id"
	authRoleKey      contextKey = "auth_role"
)

// WithProject injects the project into the context.
func WithProject(ctx context.Context, project *domain.Project) context.Context {
	return context.WithValue(ctx, projectContextKey, project)
}

// ProjectFromContext returns the project from the context, or nil.
func ProjectFromContext(ctx context.Context) *domain.Project {
	v := ctx.Value(projectContextKey)
	if v == nil {
		return nil
	}
	p, _ := v.(*domain.Project)
	return p
}

// WithAuth injects JWT-authenticated project ID, user ID, and optionally org ID and role into the context.
func WithAuth(ctx context.Context, projectID, userID, orgID, role string) context.Context {
	ctx = context.WithValue(ctx, authProjectIDKey, projectID)
	ctx = context.WithValue(ctx, authUserIDKey, userID)
	ctx = context.WithValue(ctx, authOrgIDKey, orgID)
	ctx = context.WithValue(ctx, authRoleKey, role)
	return ctx
}

// AuthFromContext returns project ID, user ID, org ID, and role from context (set by JWT middleware), or empty strings.
func AuthFromContext(ctx context.Context) (projectID, userID, orgID, role string) {
	p, _ := ctx.Value(authProjectIDKey).(string)
	u, _ := ctx.Value(authUserIDKey).(string)
	o, _ := ctx.Value(authOrgIDKey).(string)
	r, _ := ctx.Value(authRoleKey).(string)
	return p, u, o, r
}
