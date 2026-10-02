// Package rbac implements Next.Panel's role-based access control: the
// permission catalogue, default roles, role/user assignment, and the
// authorization checks every service method routes through.
//
// Authorization is always checked against permissions, never against a role
// name, so roles stay editable (Design Spec §12.1). Object-level checks are a
// required argument, not a decorator that can be forgotten (§12.3).
package rbac

import (
	"context"
	"errors"
	"fmt"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Sentinel errors.
var (
	// ErrForbidden is returned when an authenticated actor lacks the required
	// permission. The HTTP layer maps it to 403.
	ErrForbidden = errors.New("rbac: permission denied")

	// ErrNotFound is returned for an object that does not exist or is not
	// visible to the actor. Both are indistinguishable so IDs cannot be probed.
	ErrNotFound = errors.New("rbac: not found")

	// ErrInvalid is returned for a malformed role or permission.
	ErrInvalid = errors.New("rbac: invalid input")

	// ErrSystemRole is returned when a system role is edited or deleted.
	ErrSystemRole = errors.New("rbac: system roles cannot be modified")
)

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// Service provides authorization and role administration.
type Service struct {
	q     repos.Queries
	audit *audit.Writer
	log   logger
}

// New builds an RBAC service.
func New(q repos.Queries, auditWriter *audit.Writer, log logger) *Service {
	return &Service{q: q, audit: auditWriter, log: log}
}

// Can reports whether the actor holds perm, globally or — when serverID is set
// — as an explicit per-server grant (Design Spec §12.4).
func (s *Service) Can(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) (bool, error) {
	if domain.Has(actor.Permissions, perm) {
		return true, nil
	}
	if serverID == nil {
		return false, nil
	}
	grants, err := s.q.ListServerPermissions(ctx, actor.UserID, *serverID)
	if err != nil {
		return false, fmt.Errorf("rbac: load server permissions: %w", err)
	}
	return domain.Has(grants, perm), nil
}

// Require enforces perm and audits a denial. It is the function every service
// method calls before touching an object.
func (s *Service) Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error {
	ok, err := s.Can(ctx, actor, perm, serverID)
	if err != nil {
		return err
	}
	if !ok {
		s.auditDenied(ctx, actor, perm, serverID)
		return ErrForbidden
	}
	return nil
}

// RequireAny enforces that the actor holds at least one of perms.
func (s *Service) RequireAny(ctx context.Context, actor auth.Actor, serverID *domain.ServerID, perms ...domain.Permission) error {
	for _, p := range perms {
		ok, err := s.Can(ctx, actor, p, serverID)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	if len(perms) > 0 {
		s.auditDenied(ctx, actor, perms[0], serverID)
	}
	return ErrForbidden
}

// EffectiveOnServer returns the union of the actor's global permissions and
// their explicit grants on one server.
func (s *Service) EffectiveOnServer(ctx context.Context, actor auth.Actor, serverID domain.ServerID) ([]domain.Permission, error) {
	grants, err := s.q.ListServerPermissions(ctx, actor.UserID, serverID)
	if err != nil {
		return nil, fmt.Errorf("rbac: load server permissions: %w", err)
	}
	out := make([]domain.Permission, 0, len(actor.Permissions)+len(grants))
	seen := make(map[domain.Permission]struct{}, len(actor.Permissions)+len(grants))
	for _, p := range append(append([]domain.Permission{}, actor.Permissions...), grants...) {
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

// CanSeeAllServers reports whether the actor's global permissions allow
// listing every server.
func (s *Service) CanSeeAllServers(actor auth.Actor) bool {
	return domain.Has(actor.Permissions, domain.PermServersRead)
}

// CanSeeServer reports whether the actor may see one server: either they hold
// servers.read globally, or they hold any explicit grant on that server. It is
// used to turn an invisible object into a 404 rather than a 403.
func (s *Service) CanSeeServer(ctx context.Context, actor auth.Actor, serverID domain.ServerID) (bool, error) {
	if s.CanSeeAllServers(actor) {
		return true, nil
	}
	grants, err := s.q.ListServerPermissions(ctx, actor.UserID, serverID)
	if err != nil {
		return false, fmt.Errorf("rbac: load server permissions: %w", err)
	}
	return len(grants) > 0, nil
}

// AccessibleServerIDs returns the servers the actor may see. It returns nil
// with seeAll=true when the actor can see everything, so callers can skip the
// filter entirely.
func (s *Service) AccessibleServerIDs(ctx context.Context, actor auth.Actor) (ids []domain.ServerID, seeAll bool, err error) {
	if s.CanSeeAllServers(actor) {
		return nil, true, nil
	}
	ids, err = s.q.ListAccessibleServerIDs(ctx, actor.UserID)
	if err != nil {
		return nil, false, fmt.Errorf("rbac: load accessible servers: %w", err)
	}
	return ids, false, nil
}

func (s *Service) auditDenied(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) {
	if s.audit == nil {
		return
	}
	target := "permission:" + string(perm)
	meta := map[string]any{"permission": string(perm)}
	if serverID != nil {
		target = fmt.Sprintf("server:%d", *serverID)
		meta["server_id"] = int64(*serverID)
	}
	s.audit.Denied(ctx, audit.Event{
		ActorID:   &actor.UserID,
		ActorName: actor.Username,
		Action:    domain.ActionAccessDenied,
		Target:    target,
		ServerID:  serverID,
		Metadata:  meta,
	})
}
