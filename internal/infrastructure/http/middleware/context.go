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

// WithAuth injects JWT-authenticated project ID and user ID into the context.
func WithAuth(ctx context.Context, projectID, userID string) context.Context {
	ctx = context.WithValue(ctx, authProjectIDKey, projectID)
	ctx = context.WithValue(ctx, authUserIDKey, userID)
	return ctx
}

// AuthFromContext returns project ID and user ID from context (set by JWT middleware), or empty strings.
func AuthFromContext(ctx context.Context) (projectID, userID string) {
	p, _ := ctx.Value(authProjectIDKey).(string)
	u, _ := ctx.Value(authUserIDKey).(string)
	return p, u
}
