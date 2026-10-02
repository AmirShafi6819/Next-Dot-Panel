// Package server implements the managed-server domain: creation, editing,
// listing, deletion, connection testing, and host-key trust. Every method
// routes through RBAC; an object the actor cannot see is reported as missing
// (404) so server ids cannot be enumerated (Design Spec §12.3, §12.4).
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/credentials"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"
)

// Sentinel errors.
var (
	ErrNotFound  = errors.New("server: not found")
	ErrForbidden = errors.New("server: forbidden")
	ErrInvalid   = errors.New("server: invalid input")
	ErrConflict  = errors.New("server: conflict")
	ErrNoCred    = errors.New("server: credential required")
)

// Authorizer is the authorization surface the service needs; *rbac.Service
// satisfies it.
type Authorizer interface {
	Require(ctx context.Context, actor auth.Actor, perm domain.Permission, serverID *domain.ServerID) error
	CanSeeServer(ctx context.Context, actor auth.Actor, serverID domain.ServerID) (bool, error)
	CanSeeAllServers(actor auth.Actor) bool
}

type logger interface {
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

// Options configures server behaviour.
type Options struct {
	LocalExecutionEnabled bool
	CommandTimeout        time.Duration
	MaxCommandOutputBytes int64
}

// Service manages servers.
type Service struct {
	q     repos.Queries
	creds *credentials.Store
	authz Authorizer
	reg   *provider.Registry
	audit *audit.Writer
	log   logger
	opts  Options
}

// New builds the server service.
func New(q repos.Queries, creds *credentials.Store, authz Authorizer, reg *provider.Registry, auditWriter *audit.Writer, log logger, opts Options) *Service {
	return &Service{q: q, creds: creds, authz: authz, reg: reg, audit: auditWriter, log: log, opts: opts}
}

// Meta carries request context onto audit records.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

// CreateInput is the create payload.
type CreateInput struct {
	Name          string
	TargetType    domain.TargetType
	Host          string
	Port          int
	Username      string
	AuthMethod    domain.AuthMethod
	HostKeyPolicy domain.HostKeyPolicy
	Tags          []string
	Notes         string
	IsFavourite   bool
	Credential    credentials.Material
}

// UpdateInput is the update payload. Version is required for optimistic
// locking. A non-empty Credential rotates the stored credential.
type UpdateInput struct {
	Name          string
	Host          string
	Port          int
	Username      string
	AuthMethod    domain.AuthMethod
	HostKeyPolicy domain.HostKeyPolicy
	Tags          []string
	Notes         string
	IsFavourite   bool
	Version       int64
	Credential    credentials.Material
}

// Filter selects servers in a listing.
type Filter struct {
	Search     string
	Status     string
	TargetType string
	Tag        string
}

// Create adds a server. Requires servers.create.
func (s *Service) Create(ctx context.Context, actor auth.Actor, in CreateInput, meta Meta) (domain.Server, error) {
	if err := s.authz.Require(ctx, actor, domain.PermServersCreate, nil); err != nil {
		return domain.Server{}, ErrForbidden
	}
	normalizeCreate(&in)
	if err := s.validateCreate(in); err != nil {
		return domain.Server{}, err
	}
	exists, err := s.q.ServerNameExists(ctx, in.Name, 0)
	if err != nil {
		return domain.Server{}, fmt.Errorf("server: check name: %w", err)
	}
	if exists {
		return domain.Server{}, fmt.Errorf("%w: a server named %q already exists", ErrConflict, in.Name)
	}

	srv, err := s.q.CreateServer(ctx, repos.CreateServerParams{
		Name: in.Name, TargetType: in.TargetType, Host: in.Host, Port: in.Port,
		Username: in.Username, AuthMethod: in.AuthMethod, HostKeyPolicy: in.HostKeyPolicy,
		Tags: tagsJSON(in.Tags), Notes: in.Notes, IsFavourite: in.IsFavourite,
	})
	if err != nil {
		return domain.Server{}, fmt.Errorf("server: create: %w", err)
	}
	if !in.Credential.Empty() {
		if _, err := s.creds.Put(ctx, srv.ID, in.AuthMethod, in.Credential); err != nil {
			// Roll back the half-created server so the operator can retry.
			_ = s.q.DeleteServer(ctx, srv.ID)
			return domain.Server{}, fmt.Errorf("server: store credential: %w", err)
		}
	}
	s.record(ctx, actor, domain.ActionServerCreated, srv, meta, domain.ResultSuccess, nil)
	return srv, nil
}

// Get returns a server the actor can see. Visibility is any explicit grant or
// global servers.read; an invisible server is reported as missing.
func (s *Service) Get(ctx context.Context, actor auth.Actor, id domain.ServerID) (domain.Server, error) {
	return s.loadVisible(ctx, actor, id)
}

// List returns the servers the actor can see, filtered and paginated.
func (s *Service) List(ctx context.Context, actor auth.Actor, f Filter, page domain.Page) (domain.PageResult[domain.Server], error) {
	page = page.Normalize()
	search := nilIfEmpty(f.Search)
	status := nilIfEmpty(f.Status)
	target := nilIfEmpty(f.TargetType)
	tag := nilIfEmpty(f.Tag)

	if s.authz.CanSeeAllServers(actor) {
		items, err := s.q.ListServers(ctx, repos.ListServersParams{
			PageParams: repos.PageParams{Limit: int64(page.Limit()), Offset: int64(page.Offset())},
			Search:     search, Status: status, TargetType: target, Tag: tag,
		})
		if err != nil {
			return domain.PageResult[domain.Server]{}, fmt.Errorf("server: list: %w", err)
		}
		total, err := s.q.CountServers(ctx, repos.CountServersParams{Search: search, Status: status, TargetType: target, Tag: tag})
		if err != nil {
			return domain.PageResult[domain.Server]{}, fmt.Errorf("server: count: %w", err)
		}
		return domain.NewPageResult(items, total, page), nil
	}

	// Non-admins: fetch the filtered set, keep only what they can see, then
	// paginate in memory. Server counts are small; correctness beats a clever
	// join here.
	all, err := s.q.ListServers(ctx, repos.ListServersParams{
		PageParams: repos.PageParams{Limit: 100000, Offset: 0},
		Search:     search, Status: status, TargetType: target, Tag: tag,
	})
	if err != nil {
		return domain.PageResult[domain.Server]{}, fmt.Errorf("server: list: %w", err)
	}
	visible := make([]domain.Server, 0, len(all))
	for _, srv := range all {
		ok, err := s.authz.CanSeeServer(ctx, actor, srv.ID)
		if err != nil {
			return domain.PageResult[domain.Server]{}, err
		}
		if ok {
			visible = append(visible, srv)
		}
	}
	total := int64(len(visible))
	start := page.Offset()
	if start > len(visible) {
		start = len(visible)
	}
	end := start + page.Limit()
	if end > len(visible) {
		end = len(visible)
	}
	return domain.NewPageResult(visible[start:end], total, page), nil
}

// Update edits a server. Requires servers.update on the server. A changed
// credential rotates it and invalidates the pooled connection.
func (s *Service) Update(ctx context.Context, actor auth.Actor, id domain.ServerID, in UpdateInput, meta Meta) (domain.Server, error) {
	if _, err := s.loadVisible(ctx, actor, id); err != nil {
		return domain.Server{}, err
	}
	if err := s.authz.Require(ctx, actor, domain.PermServersUpdate, &id); err != nil {
		return domain.Server{}, ErrNotFound
	}
	if err := s.validateUpdate(in); err != nil {
		return domain.Server{}, err
	}
	exists, err := s.q.ServerNameExists(ctx, in.Name, id)
	if err != nil {
		return domain.Server{}, fmt.Errorf("server: check name: %w", err)
	}
	if exists {
		return domain.Server{}, fmt.Errorf("%w: a server named %q already exists", ErrConflict, in.Name)
	}

	srv, err := s.q.UpdateServer(ctx, repos.UpdateServerParams{
		ID: id, Name: in.Name, Host: in.Host, Port: in.Port, Username: in.Username,
		AuthMethod: in.AuthMethod, HostKeyPolicy: in.HostKeyPolicy,
		Tags: tagsJSON(in.Tags), Notes: in.Notes, IsFavourite: in.IsFavourite, Version: in.Version,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.Server{}, ErrConflict
		}
		return domain.Server{}, fmt.Errorf("server: update: %w", err)
	}
	if !in.Credential.Empty() {
		if _, err := s.creds.Rotate(ctx, id, in.AuthMethod, in.Credential); err != nil {
			return domain.Server{}, fmt.Errorf("server: rotate credential: %w", err)
		}
	}
	// Connection details and/or credentials changed: never reuse the old pool
	// entry (Design Spec §8.4).
	s.reg.Invalidate(ctx, id)
	s.record(ctx, actor, domain.ActionServerUpdated, srv, meta, domain.ResultSuccess, nil)
	return srv, nil
}

// Delete removes a server. Requires servers.delete on the server.
func (s *Service) Delete(ctx context.Context, actor auth.Actor, id domain.ServerID, meta Meta) error {
	srv, err := s.loadVisible(ctx, actor, id)
	if err != nil {
		return err
	}
	if err := s.authz.Require(ctx, actor, domain.PermServersDelete, &id); err != nil {
		return ErrNotFound
	}
	s.reg.Invalidate(ctx, id)
	if err := s.q.DeleteServer(ctx, id); err != nil {
		return fmt.Errorf("server: delete: %w", err)
	}
	s.record(ctx, actor, domain.ActionServerDeleted, srv, meta, domain.ResultSuccess, nil)
	return nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// loadVisible loads a server and confirms the actor may see it, returning
// ErrNotFound otherwise. This is the IDOR gate every per-object method uses.
func (s *Service) loadVisible(ctx context.Context, actor auth.Actor, id domain.ServerID) (domain.Server, error) {
	srv, err := s.q.GetServerByID(ctx, id)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Server{}, ErrNotFound
	}
	if err != nil {
		return domain.Server{}, fmt.Errorf("server: load: %w", err)
	}
	ok, err := s.authz.CanSeeServer(ctx, actor, id)
	if err != nil {
		return domain.Server{}, err
	}
	if !ok {
		return domain.Server{}, ErrNotFound
	}
	return srv, nil
}

func (s *Service) record(ctx context.Context, actor auth.Actor, action string, srv domain.Server, meta Meta, result domain.AuditResult, extra map[string]any) {
	if s.audit == nil {
		return
	}
	serverID := srv.ID
	s.audit.Record(ctx, audit.Event{
		ActorID: &actor.UserID, ActorName: actor.Username,
		Action: action, Target: fmt.Sprintf("server:%d", srv.ID),
		ServerID: &serverID, ServerName: srv.Name,
		Result: result, RequestID: meta.RequestID, IP: meta.IP, UserAgent: meta.UserAgent,
		Metadata: extra,
	})
}

func tagsJSON(tags []string) []byte {
	if tags == nil {
		tags = []string{}
	}
	b, err := json.Marshal(tags)
	if err != nil {
		return []byte("[]")
	}
	return b
}

func nilIfEmpty(s string) *string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return &s
}
