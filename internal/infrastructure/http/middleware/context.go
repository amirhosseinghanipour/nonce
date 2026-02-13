package middleware

import (
	"context"

	"github.com/amirhosseinghanipour/nonce/internal/domain"
)

type contextKey string

const projectContextKey contextKey = "project"

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
