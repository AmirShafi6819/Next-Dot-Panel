package rbac

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Meta carries request context onto audit records written by role changes.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

// RoleInput is the create/update payload for a role.
type RoleInput struct {
	Name        string
	Description string
	Permissions []domain.Permission
}

var roleNameRE = regexp.MustCompile(`^[a-z][a-z0-9_.-]{1,31}$`)

func validateRoleName(name string) error {
	if !roleNameRE.MatchString(name) {
		return fmt.Errorf("%w: role name must be 2-32 lowercase letters, digits, dot, dash or underscore", ErrInvalid)
	}
	return nil
}

func validatePermissions(perms []domain.Permission) error {
	catalogue := make(map[domain.Permission]struct{}, len(domain.AllPermissions()))
	for _, p := range domain.AllPermissions() {
		catalogue[p] = struct{}{}
	}
	for _, p := range perms {
		if _, ok := catalogue[p]; !ok {
			return fmt.Errorf("%w: unknown permission %q", ErrInvalid, p)
		}
	}
	return nil
}

// ListRoles returns every role with its permission set. Requires users.read.
func (s *Service) ListRoles(ctx context.Context, actor auth.Actor) ([]domain.Role, error) {
	if err := s.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return nil, err
	}
	roles, err := s.q.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list roles: %w", err)
	}
	for i := range roles {
		perms, err := s.q.ListRolePermissions(ctx, roles[i].ID)
		if err != nil {
			return nil, fmt.Errorf("rbac: list role permissions: %w", err)
		}
		roles[i].Permissions = perms
	}
	return roles, nil
}

// GetRole returns one role with its permissions. Requires users.read.
func (s *Service) GetRole(ctx context.Context, actor auth.Actor, id domain.RoleID) (domain.Role, error) {
	if err := s.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return domain.Role{}, err
	}
	return s.loadRole(ctx, id)
}

// ListPermissions returns the permission catalogue. Requires users.read.
func (s *Service) ListPermissions(ctx context.Context, actor auth.Actor) ([]domain.Permission, error) {
	if err := s.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return nil, err
	}
	perms, err := s.q.ListPermissions(ctx)
	if err != nil {
		return nil, fmt.Errorf("rbac: list permissions: %w", err)
	}
	return perms, nil
}

// CreateRole creates a custom role. Requires users.manage.
func (s *Service) CreateRole(ctx context.Context, actor auth.Actor, in RoleInput, meta Meta) (domain.Role, error) {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return domain.Role{}, err
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if err := validateRoleName(in.Name); err != nil {
		return domain.Role{}, err
	}
	if err := validatePermissions(in.Permissions); err != nil {
		return domain.Role{}, err
	}
	if _, err := s.q.GetRoleByName(ctx, in.Name); err == nil {
		return domain.Role{}, fmt.Errorf("%w: role %q already exists", ErrInvalid, in.Name)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.Role{}, fmt.Errorf("rbac: check role name: %w", err)
	}

	role, err := s.q.CreateRole(ctx, repos.CreateRoleParams{
		Name: in.Name, Description: in.Description, IsSystem: false,
	})
	if err != nil {
		return domain.Role{}, fmt.Errorf("rbac: create role: %w", err)
	}
	if err := s.replaceRolePermissions(ctx, role.ID, in.Permissions); err != nil {
		return domain.Role{}, err
	}
	role.Permissions = in.Permissions
	s.auditRole(ctx, actor, domain.ActionRoleChanged, role, meta, "created")
	return role, nil
}

// UpdateRole edits a custom role. Requires users.manage.
func (s *Service) UpdateRole(ctx context.Context, actor auth.Actor, id domain.RoleID, in RoleInput, meta Meta) (domain.Role, error) {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return domain.Role{}, err
	}
	existing, err := s.loadRole(ctx, id)
	if err != nil {
		return domain.Role{}, err
	}
	if existing.IsSystem {
		return domain.Role{}, ErrSystemRole
	}
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	if err := validateRoleName(in.Name); err != nil {
		return domain.Role{}, err
	}
	if err := validatePermissions(in.Permissions); err != nil {
		return domain.Role{}, err
	}

	role, err := s.q.UpdateRole(ctx, repos.UpdateRoleParams{ID: id, Name: in.Name, Description: in.Description})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Role{}, ErrNotFound
		}
		return domain.Role{}, fmt.Errorf("rbac: update role: %w", err)
	}
	if in.Permissions != nil {
		if err := s.replaceRolePermissions(ctx, id, in.Permissions); err != nil {
			return domain.Role{}, err
		}
	}
	role.Permissions = in.Permissions
	s.auditRole(ctx, actor, domain.ActionRoleChanged, role, meta, "updated")
	return role, nil
}

// DeleteRole removes a custom role. Requires users.manage.
func (s *Service) DeleteRole(ctx context.Context, actor auth.Actor, id domain.RoleID, meta Meta) error {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return err
	}
	role, err := s.loadRole(ctx, id)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return ErrSystemRole
	}
	if err := s.q.DeleteRole(ctx, id); err != nil {
		return fmt.Errorf("rbac: delete role: %w", err)
	}
	s.auditRole(ctx, actor, domain.ActionRoleChanged, role, meta, "deleted")
	return nil
}

// SetRolePermissions replaces a role's permission set. System roles may not be
// edited through the API; their permissions are reconciled at seed time.
// Requires users.manage.
func (s *Service) SetRolePermissions(ctx context.Context, actor auth.Actor, id domain.RoleID, perms []domain.Permission, meta Meta) error {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return err
	}
	role, err := s.loadRole(ctx, id)
	if err != nil {
		return err
	}
	if role.IsSystem {
		return ErrSystemRole
	}
	if err := validatePermissions(perms); err != nil {
		return err
	}
	if err := s.replaceRolePermissions(ctx, id, perms); err != nil {
		return err
	}
	role.Permissions = perms
	s.auditRole(ctx, actor, domain.ActionPermissionChanged, role, meta, "permissions set")
	return nil
}

// AssignRole grants a role to a user. Requires users.manage.
func (s *Service) AssignRole(ctx context.Context, actor auth.Actor, userID domain.UserID, roleID domain.RoleID, meta Meta) error {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return err
	}
	role, err := s.loadRole(ctx, roleID)
	if err != nil {
		return err
	}
	if _, err := s.q.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("rbac: load user: %w", err)
	}
	if err := s.q.AddUserRole(ctx, userID, roleID); err != nil {
		return fmt.Errorf("rbac: assign role: %w", err)
	}
	s.auditAssignment(ctx, actor, userID, role, meta, "assigned")
	return nil
}

// UnassignRole revokes a role from a user. Requires users.manage.
func (s *Service) UnassignRole(ctx context.Context, actor auth.Actor, userID domain.UserID, roleID domain.RoleID, meta Meta) error {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return err
	}
	role, err := s.loadRole(ctx, roleID)
	if err != nil {
		return err
	}
	if err := s.q.RemoveUserRole(ctx, userID, roleID); err != nil {
		return fmt.Errorf("rbac: unassign role: %w", err)
	}
	s.auditAssignment(ctx, actor, userID, role, meta, "unassigned")
	return nil
}

// SetUserRoles replaces a user's role set. Requires users.manage.
func (s *Service) SetUserRoles(ctx context.Context, actor auth.Actor, userID domain.UserID, roleIDs []domain.RoleID, meta Meta) error {
	if err := s.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return err
	}
	if _, err := s.q.GetUserByID(ctx, userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("rbac: load user: %w", err)
	}
	roles := make([]domain.Role, 0, len(roleIDs))
	for _, id := range roleIDs {
		role, err := s.loadRole(ctx, id)
		if err != nil {
			return err
		}
		roles = append(roles, role)
	}
	if err := s.q.ClearUserRoles(ctx, userID); err != nil {
		return fmt.Errorf("rbac: clear user roles: %w", err)
	}
	for _, role := range roles {
		if err := s.q.AddUserRole(ctx, userID, role.ID); err != nil {
			return fmt.Errorf("rbac: assign role: %w", err)
		}
	}
	if s.audit != nil {
		names := make([]string, 0, len(roles))
		for _, r := range roles {
			names = append(names, r.Name)
		}
		s.audit.Record(ctx, audit.Event{
			ActorID: &actor.UserID, ActorName: actor.Username,
			Action: domain.ActionRoleChanged, Target: fmt.Sprintf("user:%d", userID),
			Result: domain.ResultSuccess, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
			Metadata: map[string]any{"roles": names, "operation": "roles set"},
		})
	}
	return nil
}

// ListUserRoles returns the roles held by a user. Requires users.read.
func (s *Service) ListUserRoles(ctx context.Context, actor auth.Actor, userID domain.UserID) ([]domain.Role, error) {
	if err := s.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return nil, err
	}
	roles, err := s.q.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("rbac: list user roles: %w", err)
	}
	return roles, nil
}

// EffectivePermissions returns the actor's resolved global permissions. It is
// used by the /me endpoint and by tests.
func (s *Service) EffectivePermissions(ctx context.Context, userID domain.UserID) ([]domain.Permission, error) {
	perms, err := s.q.ListUserPermissions(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("rbac: list user permissions: %w", err)
	}
	return perms, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (s *Service) loadRole(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	role, err := s.q.GetRoleByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Role{}, ErrNotFound
	}
	if err != nil {
		return domain.Role{}, fmt.Errorf("rbac: load role: %w", err)
	}
	perms, err := s.q.ListRolePermissions(ctx, id)
	if err != nil {
		return domain.Role{}, fmt.Errorf("rbac: load role permissions: %w", err)
	}
	role.Permissions = perms
	return role, nil
}

func (s *Service) replaceRolePermissions(ctx context.Context, id domain.RoleID, perms []domain.Permission) error {
	if err := s.q.ClearRolePermissions(ctx, id); err != nil {
		return fmt.Errorf("rbac: clear role permissions: %w", err)
	}
	for _, p := range perms {
		if err := s.q.AddRolePermission(ctx, id, p); err != nil {
			return fmt.Errorf("rbac: add role permission: %w", err)
		}
	}
	return nil
}

func (s *Service) auditRole(ctx context.Context, actor auth.Actor, action string, role domain.Role, meta Meta, operation string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: &actor.UserID, ActorName: actor.Username,
		Action: action, Target: fmt.Sprintf("role:%d", role.ID),
		Result: domain.ResultSuccess, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: map[string]any{"role": role.Name, "operation": operation},
	})
}

func (s *Service) auditAssignment(ctx context.Context, actor auth.Actor, userID domain.UserID, role domain.Role, meta Meta, operation string) {
	if s.audit == nil {
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: &actor.UserID, ActorName: actor.Username,
		Action: domain.ActionRoleChanged, Target: fmt.Sprintf("user:%d", userID),
		Result: domain.ResultSuccess, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: map[string]any{"role": role.Name, "operation": operation},
	})
}
