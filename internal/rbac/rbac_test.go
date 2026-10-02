package rbac

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	pg "github.com/ashaibery/Next-Dot-Panel/internal/store/postgres"
	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

const pgRBACTestSchema = "nextpanel_rbac_test"

type env struct {
	svc *Service
	q   repos.Queries
}

func forEachDialect(t *testing.T, fn func(t *testing.T, e env)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, openSQLite(t)) })
	t.Run("postgres", func(t *testing.T) {
		e, ok := openPostgres(t)
		if !ok {
			t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL rbac test")
		}
		fn(t, e)
	})
}

func openSQLite(t *testing.T) env {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dir, "rbac.db"), MaxConns: 1},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	q := repos.NewSQLiteQueries(lite.New(db.DB))
	return env{svc: New(q, audit.New(q, nil), nil), q: q}
}

func openPostgres(t *testing.T) (env, bool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		return env{}, false
	}
	if os.Getenv("NEXT_PANEL_ENV") == "production" {
		t.Fatal("refusing to run destructive rbac tests with NEXT_PANEL_ENV=production")
	}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse TEST_DATABASE_URL: %v", err)
		}
		q := u.Query()
		q.Set("search_path", pgRBACTestSchema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + pgRBACTestSchema
	}
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: t.TempDir(), LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverPostgres, DSN: dsn, MaxConns: 5},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+pgRBACTestSchema+" CASCADE; CREATE SCHEMA "+pgRBACTestSchema+";"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	q := repos.NewPostgresQueries(pg.New(db.PGXPool()))
	return env{svc: New(q, audit.New(q, nil), nil), q: q}, true
}

func createUser(t *testing.T, q repos.Queries, name string) domain.User {
	t.Helper()
	u, err := q.CreateUser(context.Background(), repos.CreateUserParams{
		Username: name, PasswordHash: "argon2id$fake", DisplayName: name, IsActive: true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func actorFor(u domain.User, perms ...domain.Permission) auth.Actor {
	return auth.Actor{UserID: u.ID, Username: u.Username, SessionID: "ses_test", Permissions: perms}
}

func TestSeedCreatesCatalogueAndRoles(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		perms, err := e.q.ListPermissions(ctx)
		if err != nil {
			t.Fatalf("ListPermissions: %v", err)
		}
		if len(perms) != len(domain.AllPermissions()) {
			t.Fatalf("permission count = %d, want %d", len(perms), len(domain.AllPermissions()))
		}
		admin, err := e.q.GetRoleByName(ctx, domain.RoleAdmin)
		if err != nil {
			t.Fatalf("GetRoleByName(admin): %v", err)
		}
		if !admin.IsSystem {
			t.Fatal("admin role should be a system role")
		}
		adminPerms, err := e.q.ListRolePermissions(ctx, admin.ID)
		if err != nil {
			t.Fatalf("admin perms: %v", err)
		}
		if len(adminPerms) != len(domain.AllPermissions()) {
			t.Fatalf("admin has %d permissions, want all %d", len(adminPerms), len(domain.AllPermissions()))
		}
		operator, err := e.q.GetRoleByName(ctx, domain.RoleOperator)
		if err != nil {
			t.Fatalf("operator: %v", err)
		}
		opPerms, _ := e.q.ListRolePermissions(ctx, operator.ID)
		if domain.Has(opPerms, domain.PermUsersManage) {
			t.Fatal("operator must not manage users")
		}
		viewer, err := e.q.GetRoleByName(ctx, domain.RoleViewer)
		if err != nil {
			t.Fatalf("viewer: %v", err)
		}
		vPerms, _ := e.q.ListRolePermissions(ctx, viewer.ID)
		if domain.Has(vPerms, domain.PermServersUpdate) || domain.Has(vPerms, domain.PermTerminalOpen) {
			t.Fatal("viewer must be read-only")
		}

		// Idempotent.
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("second Seed: %v", err)
		}
		perms2, _ := e.q.ListPermissions(ctx)
		if len(perms2) != len(perms) {
			t.Fatalf("second seed changed permission count: %d -> %d", len(perms), len(perms2))
		}
	})
}

func TestRequireAndDenialAudit(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		u := createUser(t, e.q, "alice")

		authorized := actorFor(u, domain.PermServersRead)
		if err := e.svc.Require(ctx, authorized, domain.PermServersRead, nil); err != nil {
			t.Fatalf("Require(servers.read) = %v, want nil", err)
		}
		denied := actorFor(u, domain.PermServersRead)
		if err := e.svc.Require(ctx, denied, domain.PermServersDelete, nil); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Require(servers.delete) = %v, want ErrForbidden", err)
		}

		action := domain.ActionAccessDenied
		events, err := e.q.ListAudit(ctx, repos.AuditQueryParams{Action: &action, PageParams: repos.PageParams{Limit: 10}})
		if err != nil {
			t.Fatalf("ListAudit: %v", err)
		}
		if len(events) == 0 || events[0].Result != domain.ResultDenied {
			t.Fatalf("denial was not audited as DENIED: %+v", events)
		}
	})
}

func TestPerServerScoping(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		u := createUser(t, e.q, "bob")
		s1 := createServer(t, e.q, "s1")
		s2 := createServer(t, e.q, "s2")

		// Grant terminal.open on s1 only.
		if err := e.q.GrantServerPermission(ctx, repos.GrantServerPermissionParams{
			UserID: u.ID, ServerID: s1, Permission: domain.PermTerminalOpen,
		}); err != nil {
			t.Fatalf("GrantServerPermission: %v", err)
		}
		actor := actorFor(u) // no global permissions

		if err := e.svc.Require(ctx, actor, domain.PermTerminalOpen, &s1); err != nil {
			t.Fatalf("Require on granted server = %v, want nil", err)
		}
		if err := e.svc.Require(ctx, actor, domain.PermTerminalOpen, &s2); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Require on ungranted server = %v, want ErrForbidden", err)
		}
		if err := e.svc.Require(ctx, actor, domain.PermTerminalOpen, nil); !errors.Is(err, ErrForbidden) {
			t.Fatalf("Require global = %v, want ErrForbidden", err)
		}

		ids, seeAll, err := e.svc.AccessibleServerIDs(ctx, actor)
		if err != nil {
			t.Fatalf("AccessibleServerIDs: %v", err)
		}
		if seeAll || len(ids) != 1 || ids[0] != s1 {
			t.Fatalf("accessible = %v seeAll=%v, want [%d]", ids, seeAll, s1)
		}

		admin := actorFor(u, domain.PermServersRead)
		if _, seeAll, _ := e.svc.AccessibleServerIDs(ctx, admin); !seeAll {
			t.Fatal("actor with servers.read should see all servers")
		}

		eff, err := e.svc.EffectiveOnServer(ctx, actorFor(u, domain.PermServersRead), s1)
		if err != nil {
			t.Fatalf("EffectiveOnServer: %v", err)
		}
		if !domain.Has(eff, domain.PermServersRead) || !domain.Has(eff, domain.PermTerminalOpen) {
			t.Fatalf("effective permissions = %v, want union", eff)
		}
	})
}

func TestRoleLifecycle(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		admin := actorFor(createUser(t, e.q, "root"), domain.PermUsersRead, domain.PermUsersManage)

		role, err := e.svc.CreateRole(ctx, admin, RoleInput{
			Name: "auditor", Description: "reads audit", Permissions: []domain.Permission{domain.PermAuditRead},
		}, Meta{})
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if role.Name != "auditor" || !domain.Has(role.Permissions, domain.PermAuditRead) {
			t.Fatalf("unexpected role: %+v", role)
		}
		if _, err := e.svc.CreateRole(ctx, admin, RoleInput{Name: "auditor"}, Meta{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("duplicate role err = %v, want ErrInvalid", err)
		}
		if _, err := e.svc.CreateRole(ctx, admin, RoleInput{Name: "Bad Name"}, Meta{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad name err = %v, want ErrInvalid", err)
		}
		if _, err := e.svc.CreateRole(ctx, admin, RoleInput{Name: "x", Permissions: []domain.Permission{"nope.nope"}}, Meta{}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("bad permission err = %v, want ErrInvalid", err)
		}

		if _, err := e.svc.UpdateRole(ctx, admin, role.ID, RoleInput{Name: "auditor2", Permissions: []domain.Permission{domain.PermAuditRead, domain.PermServersRead}}, Meta{}); err != nil {
			t.Fatalf("UpdateRole: %v", err)
		}
		got, err := e.svc.GetRole(ctx, admin, role.ID)
		if err != nil {
			t.Fatalf("GetRole: %v", err)
		}
		if got.Name != "auditor2" || len(got.Permissions) != 2 {
			t.Fatalf("unexpected updated role: %+v", got)
		}

		// System roles are protected.
		adminRole, _ := e.q.GetRoleByName(ctx, domain.RoleAdmin)
		if _, err := e.svc.UpdateRole(ctx, admin, adminRole.ID, RoleInput{Name: "admin"}, Meta{}); !errors.Is(err, ErrSystemRole) {
			t.Fatalf("edit system role err = %v, want ErrSystemRole", err)
		}
		if err := e.svc.DeleteRole(ctx, admin, adminRole.ID, Meta{}); !errors.Is(err, ErrSystemRole) {
			t.Fatalf("delete system role err = %v, want ErrSystemRole", err)
		}
		if err := e.svc.SetRolePermissions(ctx, admin, adminRole.ID, nil, Meta{}); !errors.Is(err, ErrSystemRole) {
			t.Fatalf("set system perms err = %v, want ErrSystemRole", err)
		}

		if err := e.svc.DeleteRole(ctx, admin, role.ID, Meta{}); err != nil {
			t.Fatalf("DeleteRole: %v", err)
		}
		if _, err := e.svc.GetRole(ctx, admin, role.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("GetRole after delete = %v, want ErrNotFound", err)
		}
	})
}

func TestRoleAssignment(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		admin := actorFor(createUser(t, e.q, "root"), domain.PermUsersRead, domain.PermUsersManage)
		target := createUser(t, e.q, "carol")
		viewer, _ := e.q.GetRoleByName(ctx, domain.RoleViewer)
		operator, _ := e.q.GetRoleByName(ctx, domain.RoleOperator)

		if err := e.svc.AssignRole(ctx, admin, target.ID, viewer.ID, Meta{}); err != nil {
			t.Fatalf("AssignRole: %v", err)
		}
		if err := e.svc.AssignRole(ctx, admin, target.ID, operator.ID, Meta{}); err != nil {
			t.Fatalf("AssignRole operator: %v", err)
		}
		roles, err := e.svc.ListUserRoles(ctx, admin, target.ID)
		if err != nil {
			t.Fatalf("ListUserRoles: %v", err)
		}
		if len(roles) != 2 {
			t.Fatalf("roles = %d, want 2", len(roles))
		}

		if err := e.svc.SetUserRoles(ctx, admin, target.ID, []domain.RoleID{viewer.ID}, Meta{}); err != nil {
			t.Fatalf("SetUserRoles: %v", err)
		}
		roles, _ = e.svc.ListUserRoles(ctx, admin, target.ID)
		if len(roles) != 1 || roles[0].Name != domain.RoleViewer {
			t.Fatalf("after SetUserRoles roles = %+v", roles)
		}

		if err := e.svc.UnassignRole(ctx, admin, target.ID, viewer.ID, Meta{}); err != nil {
			t.Fatalf("UnassignRole: %v", err)
		}
		if roles, _ := e.svc.ListUserRoles(ctx, admin, target.ID); len(roles) != 0 {
			t.Fatalf("roles after unassign = %+v", roles)
		}
	})
}

func TestEnsureBootstrapAdminRole(t *testing.T) {
	forEachDialect(t, func(t *testing.T, e env) {
		ctx := context.Background()
		if err := e.svc.Seed(ctx); err != nil {
			t.Fatalf("Seed: %v", err)
		}
		createUser(t, e.q, "admin")

		if err := e.svc.EnsureBootstrapAdminRole(ctx, "admin"); err != nil {
			t.Fatalf("EnsureBootstrapAdminRole: %v", err)
		}
		u, _ := e.q.GetUserByUsername(ctx, "admin")
		roles, _ := e.q.ListUserRoles(ctx, u.ID)
		if len(roles) != 1 || roles[0].Name != domain.RoleAdmin {
			t.Fatalf("bootstrap roles = %+v, want admin", roles)
		}

		// Existing roles are not clobbered.
		if err := e.svc.EnsureBootstrapAdminRole(ctx, "admin"); err != nil {
			t.Fatalf("second EnsureBootstrapAdminRole: %v", err)
		}
		if roles, _ := e.q.ListUserRoles(ctx, u.ID); len(roles) != 1 {
			t.Fatalf("bootstrap roles changed: %+v", roles)
		}
	})
}

func createServer(t *testing.T, q repos.Queries, name string) domain.ServerID {
	t.Helper()
	s, err := q.CreateServer(context.Background(), repos.CreateServerParams{
		Name: name, TargetType: domain.TargetSSH, Host: "127.0.0.1", Port: 22,
		Username: "root", AuthMethod: domain.AuthKey, HostKeyPolicy: domain.HostKeyStrict,
		Tags: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	return s.ID
}
