package audit

import (
	"context"
	"errors"
	"fmt"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Authorizer enforces permissions (satisfied by *rbac.Service).
type Authorizer interface {
	Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error
}

// ErrForbidden is returned for an actor lacking audit.read.
var ErrForbidden = errors.New("audit: forbidden")

// Query reads the audit trail. Writing stays in Writer; reading lives here so
// both share one permission gate.
type Query struct {
	q     repos.Queries
	authz Authorizer
}

// NewQuery builds an audit reader.
func NewQuery(q repos.Queries, authz Authorizer) *Query {
	return &Query{q: q, authz: authz}
}

// List returns audit events matching the filter. Requires audit.read.
func (qq *Query) List(ctx context.Context, actor auth.Actor, p repos.AuditQueryParams) ([]domain.AuditEvent, error) {
	if err := qq.authz.Require(ctx, actor, domain.PermAuditRead, nil); err != nil {
		return nil, ErrForbidden
	}
	if p.Limit <= 0 || p.Limit > domain.MaxPerPage {
		p.Limit = domain.DefaultPerPage
	}
	events, err := qq.q.ListAudit(ctx, p)
	if err != nil {
		return nil, fmt.Errorf("audit: list: %w", err)
	}
	return events, nil
}

// Count returns the number of matching events. Requires audit.read.
func (qq *Query) Count(ctx context.Context, actor auth.Actor, p repos.AuditQueryParams) (int64, error) {
	if err := qq.authz.Require(ctx, actor, domain.PermAuditRead, nil); err != nil {
		return 0, ErrForbidden
	}
	n, err := qq.q.CountAudit(ctx, p)
	if err != nil {
		return 0, fmt.Errorf("audit: count: %w", err)
	}
	return n, nil
}
