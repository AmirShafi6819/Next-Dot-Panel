package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// roleSeed describes a default (system) role.
type roleSeed struct {
	name        string
	description string
	perms       []domain.Permission
}

// defaultRoles returns the canonical system roles (Design Spec §12.1). System
// roles are reconciled to these permission sets on every start; they are not
// editable through the API, so an operator cannot lock themselves out of the
// admin role by accident.
func defaultRoles() []roleSeed {
	all := domain.AllPermissions()

	operatorExcluded := map[domain.Permission]struct{}{
		domain.PermUsersRead:      {},
		domain.PermUsersManage:    {},
		domain.PermSettingsManage: {},
		domain.PermAuditRead:      {},
		domain.PermBackupsRestore: {},
	}
	operator := make([]domain.Permission, 0, len(all))
	for _, p := range all {
		if _, skip := operatorExcluded[p]; !skip {
			operator = append(operator, p)
		}
	}

	viewer := []domain.Permission{
		domain.PermServersRead,
		domain.PermFilesRead,
		domain.PermMetricsRead,
		domain.PermProcessesRead,
		domain.PermServicesRead,
		domain.PermContainersRead,
		domain.PermBackupsRead,
	}

	return []roleSeed{
		{name: domain.RoleAdmin, description: "Full access, including users and settings", perms: all},
		{name: domain.RoleOperator, description: "Full server operations; cannot manage users or global settings", perms: operator},
		{name: domain.RoleViewer, description: "Read-only access to servers and monitoring", perms: viewer},
	}
}

// Seed makes the permission catalogue and the default roles present. It is
// idempotent and runs at startup after migrations (Design Spec §12).
func (s *Service) Seed(ctx context.Context) error {
	if err := s.seedPermissions(ctx); err != nil {
		return err
	}
	return s.seedRoles(ctx)
}

func (s *Service) seedPermissions(ctx context.Context) error {
	existing, err := s.q.ListPermissions(ctx)
	if err != nil {
		return fmt.Errorf("rbac: list permissions: %w", err)
	}
	have := make(map[domain.Permission]struct{}, len(existing))
	for _, p := range existing {
		have[p] = struct{}{}
	}
	for _, p := range domain.AllPermissions() {
		if _, ok := have[p]; ok {
			continue
		}
		desc := domain.PermissionDescriptions[p]
		if err := s.q.CreatePermission(ctx, repos.CreatePermissionParams{Name: p, Description: desc}); err != nil {
			return fmt.Errorf("rbac: seed permission %q: %w", p, err)
		}
	}
	return nil
}

func (s *Service) seedRoles(ctx context.Context) error {
	for _, seed := range defaultRoles() {
		role, err := s.q.GetRoleByName(ctx, seed.name)
		if errors.Is(err, sql.ErrNoRows) {
			role, err = s.q.CreateRole(ctx, repos.CreateRoleParams{
				Name: seed.name, Description: seed.description, IsSystem: true,
			})
			if err != nil {
				return fmt.Errorf("rbac: seed role %q: %w", seed.name, err)
			}
		} else if err != nil {
			return fmt.Errorf("rbac: load role %q: %w", seed.name, err)
		}
		if err := s.replaceRolePermissions(ctx, role.ID, seed.perms); err != nil {
			return fmt.Errorf("rbac: seed role %q permissions: %w", seed.name, err)
		}
	}
	return nil
}

// EnsureBootstrapAdminRole grants the admin role to the bootstrap
// administrator when it holds no role yet. It is safe to call on every start:
// a user who already has any role is left untouched, so an operator can safely
// narrow the bootstrap account later.
func (s *Service) EnsureBootstrapAdminRole(ctx context.Context, username string) error {
	if username == "" {
		return nil
	}
	user, err := s.q.GetUserByUsername(ctx, username)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("rbac: load bootstrap user: %w", err)
	}
	roles, err := s.q.ListUserRoles(ctx, user.ID)
	if err != nil {
		return fmt.Errorf("rbac: list bootstrap roles: %w", err)
	}
	if len(roles) > 0 {
		return nil
	}
	admin, err := s.q.GetRoleByName(ctx, domain.RoleAdmin)
	if err != nil {
		return fmt.Errorf("rbac: load admin role: %w", err)
	}
	if err := s.q.AddUserRole(ctx, user.ID, admin.ID); err != nil {
		return fmt.Errorf("rbac: grant admin role: %w", err)
	}
	if s.log != nil {
		s.log.Warn(ctx, "granted the admin role to the bootstrap administrator", "username", username)
	}
	return nil
}
