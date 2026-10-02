// Package users implements account administration: creation, editing,
// disabling, deletion, password resets and session revocation. Self-service
// password changes live in internal/auth; this package is the administrator's
// side. Deleting the last active administrator or your own account is refused.
package users

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

// Sentinel errors.
var (
	ErrNotFound  = errors.New("users: not found")
	ErrForbidden = errors.New("users: forbidden")
	ErrInvalid   = errors.New("users: invalid input")
	ErrConflict  = errors.New("users: conflict")
	ErrLastAdmin = errors.New("users: cannot remove the last active administrator")
	ErrSelf      = errors.New("users: cannot perform this action on your own account")
)

// Authorizer enforces permissions (satisfied by *rbac.Service).
type Authorizer interface {
	Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
}

// Service administers accounts.
type Service struct {
	q     repos.Queries
	authz Authorizer
	audit *audit.Writer
	log   logger
}

// New builds the users service.
func New(q repos.Queries, authz Authorizer, auditWriter *audit.Writer, log logger) *Service {
	return &Service{q: q, authz: authz, audit: auditWriter, log: log}
}

// Meta carries request context onto audit records.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

var usernameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{2,31}$`)

func validateUsername(username string) error {
	if !usernameRE.MatchString(username) {
		return fmt.Errorf("%w: username must be 3-32 characters, letters/digits/dot/dash/underscore", ErrInvalid)
	}
	return nil
}

// CreateInput is the create payload.
type CreateInput struct {
	Username    string
	DisplayName string
	Password    string
	IsActive    bool
	RoleIDs     []domain.RoleID
}

// Create adds an account. Requires users.manage.
func (s *Service) Create(ctx context.Context, actor auth.Actor, in CreateInput, meta Meta) (domain.User, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return domain.User{}, ErrForbidden
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := validateUsername(in.Username); err != nil {
		return domain.User{}, err
	}
	if err := auth.ValidatePassword(in.Password); err != nil {
		return domain.User{}, err
	}
	if _, err := s.q.GetUserByUsername(ctx, in.Username); err == nil {
		return domain.User{}, fmt.Errorf("%w: username is taken", ErrConflict)
	} else if !errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, fmt.Errorf("users: check username: %w", err)
	}
	hash, err := auth.Hash(in.Password)
	if err != nil {
		return domain.User{}, err
	}
	u, err := s.q.CreateUser(ctx, repos.CreateUserParams{
		Username: in.Username, PasswordHash: hash, DisplayName: in.DisplayName, IsActive: in.IsActive,
	})
	if err != nil {
		return domain.User{}, fmt.Errorf("users: create: %w", err)
	}
	for _, rid := range in.RoleIDs {
		if _, rerr := s.q.GetRoleByID(ctx, rid); rerr != nil {
			_ = s.q.SoftDeleteUser(ctx, u.ID)
			if errors.Is(rerr, sql.ErrNoRows) {
				return domain.User{}, ErrNotFound
			}
			return domain.User{}, fmt.Errorf("users: load role: %w", rerr)
		}
		if rerr := s.q.AddUserRole(ctx, u.ID, rid); rerr != nil {
			_ = s.q.SoftDeleteUser(ctx, u.ID)
			return domain.User{}, fmt.Errorf("users: assign role: %w", rerr)
		}
	}
	s.record(ctx, actor, domain.ActionUserCreated, u, meta)
	return s.withRoles(ctx, u)
}

// Get returns an account with its roles. Requires users.read.
func (s *Service) Get(ctx context.Context, actor auth.Actor, id domain.UserID) (domain.User, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return domain.User{}, ErrForbidden
	}
	u, err := s.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, ErrNotFound
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("users: load: %w", err)
	}
	return s.withRoles(ctx, u)
}

// List returns accounts matching the filters. Requires users.read.
func (s *Service) List(ctx context.Context, actor auth.Actor, search string, isActive *bool, limit, offset int64) ([]domain.User, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return nil, ErrForbidden
	}
	if limit <= 0 || limit > domain.MaxPerPage {
		limit = domain.DefaultPerPage
	}
	var searchPtr *string
	if strings.TrimSpace(search) != "" {
		searchPtr = &search
	}
	users, err := s.q.ListUsers(ctx, repos.ListUsersParams{
		PageParams: repos.PageParams{Limit: limit, Offset: offset},
		Search:     searchPtr, IsActive: isActive,
	})
	if err != nil {
		return nil, fmt.Errorf("users: list: %w", err)
	}
	return users, nil
}

// UpdateInput edits display name and active state.
type UpdateInput struct {
	DisplayName string
	IsActive    bool
	Version     int64
}

// Update edits an account. Requires users.manage. Disabling yourself is
// refused; disabling the last active administrator is refused.
func (s *Service) Update(ctx context.Context, actor auth.Actor, id domain.UserID, in UpdateInput, meta Meta) (domain.User, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return domain.User{}, ErrForbidden
	}
	target, err := s.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.User{}, ErrNotFound
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("users: load: %w", err)
	}
	if id == actor.UserID && !in.IsActive {
		return domain.User{}, ErrSelf
	}
	if target.IsActive && !in.IsActive {
		if err := s.guardLastAdmin(ctx, id); err != nil {
			return domain.User{}, err
		}
	}
	u, err := s.q.UpdateUser(ctx, repos.UpdateUserParams{
		ID: id, DisplayName: in.DisplayName, IsActive: in.IsActive, Version: in.Version,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.User{}, ErrConflict
		}
		return domain.User{}, fmt.Errorf("users: update: %w", err)
	}
	action := domain.ActionUserUpdated
	if target.IsActive && !in.IsActive {
		action = domain.ActionUserDisabled
	} else if !target.IsActive && in.IsActive {
		action = domain.ActionUserEnabled
	}
	s.record(ctx, actor, action, u, meta)
	return s.withRoles(ctx, u)
}

// Delete soft-deletes an account and revokes its sessions. Requires
// users.manage. Deleting yourself or the last active administrator is refused;
// audit records keep the denormalised actor name.
func (s *Service) Delete(ctx context.Context, actor auth.Actor, id domain.UserID, meta Meta) error {
	if err := s.authz.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return ErrForbidden
	}
	if id == actor.UserID {
		return ErrSelf
	}
	target, err := s.q.GetUserByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("users: load: %w", err)
	}
	if target.IsActive {
		if err := s.guardLastAdmin(ctx, id); err != nil {
			return err
		}
	}
	if _, err := s.q.RevokeUserSessions(ctx, id); err != nil {
		return fmt.Errorf("users: revoke sessions: %w", err)
	}
	if err := s.q.SoftDeleteUser(ctx, id); err != nil {
		return fmt.Errorf("users: delete: %w", err)
	}
	s.record(ctx, actor, domain.ActionUserDeleted, target, meta)
	return nil
}

// ResetPassword sets a new password and forces a change at next login.
// Requires users.manage.
func (s *Service) ResetPassword(ctx context.Context, actor auth.Actor, id domain.UserID, newPassword string, meta Meta) error {
	if err := s.authz.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return ErrForbidden
	}
	if err := auth.ValidatePassword(newPassword); err != nil {
		return err
	}
	if _, err := s.q.GetUserByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("users: load: %w", err)
	}
	hash, err := auth.Hash(newPassword)
	if err != nil {
		return err
	}
	if _, err := s.q.SetUserPassword(ctx, repos.SetUserPasswordParams{
		ID: id, PasswordHash: hash, MustChange: true,
	}); err != nil {
		return fmt.Errorf("users: reset password: %w", err)
	}
	if _, err := s.q.RevokeUserSessions(ctx, id); err != nil {
		return fmt.Errorf("users: revoke sessions: %w", err)
	}
	u, _ := s.q.GetUserByID(ctx, id)
	s.record(ctx, actor, domain.ActionPasswordReset, u, meta)
	return nil
}

// RevokeSessions revokes all of a user's sessions. Requires users.manage.
func (s *Service) RevokeSessions(ctx context.Context, actor auth.Actor, id domain.UserID, meta Meta) (int64, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersManage, nil); err != nil {
		return 0, ErrForbidden
	}
	if _, err := s.q.GetUserByID(ctx, id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("users: load: %w", err)
	}
	n, err := s.q.RevokeUserSessions(ctx, id)
	if err != nil {
		return 0, fmt.Errorf("users: revoke sessions: %w", err)
	}
	return n, nil
}

// ListLoginHistory returns login attempts. Requires users.read.
func (s *Service) ListLoginHistory(ctx context.Context, actor auth.Actor, userID *domain.UserID, success *bool, limit, offset int64) ([]domain.LoginAttempt, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return nil, ErrForbidden
	}
	if limit <= 0 || limit > domain.MaxPerPage {
		limit = domain.DefaultPerPage
	}
	attempts, err := s.q.ListLoginHistory(ctx, repos.LoginHistoryParams{
		PageParams: repos.PageParams{Limit: limit, Offset: offset},
		UserID:     userID, Success: success,
	})
	if err != nil {
		return nil, fmt.Errorf("users: login history: %w", err)
	}
	return attempts, nil
}

// Count returns the number of accounts matching the filters. Requires
// users.read.
func (s *Service) Count(ctx context.Context, actor auth.Actor, search string, isActive *bool) (int64, error) {
	if err := s.authz.Require(ctx, actor, domain.PermUsersRead, nil); err != nil {
		return 0, ErrForbidden
	}
	var searchPtr *string
	if strings.TrimSpace(search) != "" {
		searchPtr = &search
	}
	n, err := s.q.CountUsers(ctx, repos.CountUsersParams{Search: searchPtr, IsActive: isActive})
	if err != nil {
		return 0, fmt.Errorf("users: count: %w", err)
	}
	return n, nil
}

func (s *Service) guardLastAdmin(ctx context.Context, id domain.UserID) error {
	// An administrator is a user holding the admin role; removing or disabling
	// the last active one would lock out administration.
	roles, err := s.q.ListUserRoles(ctx, id)
	if err != nil {
		return fmt.Errorf("users: load roles: %w", err)
	}
	isAdmin := false
	for _, r := range roles {
		if r.Name == domain.RoleAdmin {
			isAdmin = true
			break
		}
	}
	if !isAdmin {
		return nil
	}
	count, err := s.q.CountActiveAdmins(ctx)
	if err != nil {
		return fmt.Errorf("users: count admins: %w", err)
	}
	if count <= 1 {
		return ErrLastAdmin
	}
	return nil
}

func (s *Service) withRoles(ctx context.Context, u domain.User) (domain.User, error) {
	roles, err := s.q.ListUserRoles(ctx, u.ID)
	if err != nil {
		return u, fmt.Errorf("users: load roles: %w", err)
	}
	u.Roles = roles
	return u, nil
}

func (s *Service) record(ctx context.Context, actor auth.Actor, action string, u domain.User, meta Meta) {
	if s.audit == nil {
		return
	}
	s.audit.Record(ctx, audit.Event{
		ActorID: &actor.UserID, ActorName: actor.Username,
		Action: action, Target: fmt.Sprintf("user:%d", u.ID),
		Result: domain.ResultSuccess, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: map[string]any{"username": u.Username},
	})
}
