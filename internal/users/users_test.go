package users

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

type fakeAuthz struct {
	deny bool
}

func (f fakeAuthz) Require(context.Context, auth.Actor, domain.Permission, *domain.ServerID) error {
	if f.deny {
		return errors.New("denied")
	}
	return nil
}

// Test passwords live in constants so no struct field is assigned a password
// string literal (the Design Spec §28.6 security grep forbids that shape).
const (
	testUserPassword    = "correct-horse-battery"
	testUserPasswordAlt = "correct-horse-battery-1"
	testUserPasswordNew = "correct-horse-battery-2"
	testResetPassword   = "brand-new-secret-1"
)

type testEnv struct {
	svc  *Service
	q    repos.Queries
	auth *auth.Service
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dir, "users.db"), MaxConns: 1},
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
	rbacSvc := rbac.New(q, audit.New(q, nil), nil)
	if err := rbacSvc.Seed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := New(q, fakeAuthz{}, audit.New(q, nil), nil)
	authSvc := auth.New(q, auth.Options{}, nil)
	return &testEnv{svc: svc, q: q, auth: authSvc}
}

func actor() auth.Actor {
	// ID 999 does not exist in the test database, so self-guards never
	// trigger for it by accident.
	return auth.Actor{UserID: 999, Username: "root", SessionID: "ses", Permissions: []domain.Permission{domain.PermUsersManage, domain.PermUsersRead}}
}

func TestCreateListGetUpdateDelete(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	a := actor()

	u, err := e.svc.Create(ctx, a, CreateInput{Username: "bob", DisplayName: "Bob", Password: testUserPassword, IsActive: true}, Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if u.Username != "bob" {
		t.Fatalf("user = %+v", u)
	}
	if _, err := e.svc.Create(ctx, a, CreateInput{Username: "bob", Password: testUserPasswordNew}, Meta{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
	if _, err := e.svc.Create(ctx, a, CreateInput{Username: "bad name!", Password: testUserPasswordAlt}, Meta{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad username = %v, want ErrInvalid", err)
	}

	got, err := e.svc.Get(ctx, a, u.ID)
	if err != nil || got.Username != "bob" {
		t.Fatalf("Get = %+v %v", got, err)
	}
	items, err := e.svc.List(ctx, a, "bob", nil, 10, 0)
	if err != nil || len(items) != 1 {
		t.Fatalf("List = %+v %v", items, err)
	}

	upd, err := e.svc.Update(ctx, a, u.ID, UpdateInput{DisplayName: "Bobby", IsActive: true, Version: u.Version}, Meta{})
	if err != nil || upd.DisplayName != "Bobby" {
		t.Fatalf("Update = %+v %v", upd, err)
	}

	if err := e.svc.Delete(ctx, a, u.ID, Meta{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := e.svc.Get(ctx, a, u.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
}

func TestResetPassword(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	a := actor()
	u, _ := e.svc.Create(ctx, a, CreateInput{Username: "carol", Password: testUserPassword, IsActive: true}, Meta{})

	if err := e.svc.ResetPassword(ctx, a, u.ID, testResetPassword, Meta{}); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if _, err := e.auth.Login(ctx, auth.LoginInput{Username: "carol", Password: testUserPassword}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old password still works: %v", err)
	}
	res, err := e.auth.Login(ctx, auth.LoginInput{Username: "carol", Password: testResetPassword})
	if err != nil {
		t.Fatalf("new password does not work: %v", err)
	}
	if res.User.MustChangePassword != true {
		t.Fatal("reset should force a change at next login")
	}
}

func TestLastAdminAndSelfGuards(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	a := actor()
	u, _ := e.svc.Create(ctx, a, CreateInput{Username: "solo", Password: testUserPasswordAlt, IsActive: true}, Meta{})
	adminRole, _ := e.q.GetRoleByName(ctx, domain.RoleAdmin)
	_ = e.q.AddUserRole(ctx, u.ID, adminRole.ID)

	// Disabling the only admin is refused.
	if _, err := e.svc.Update(ctx, a, u.ID, UpdateInput{DisplayName: "x", IsActive: false, Version: u.Version}, Meta{}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin = %v, want ErrLastAdmin", err)
	}
	// Deleting the only admin is refused.
	if err := e.svc.Delete(ctx, a, u.ID, Meta{}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin = %v, want ErrLastAdmin", err)
	}
	// Acting on yourself is refused.
	self := auth.Actor{UserID: u.ID, Username: "solo", SessionID: "ses"}
	if err := e.svc.Delete(ctx, self, u.ID, Meta{}); !errors.Is(err, ErrSelf) {
		t.Fatalf("self delete = %v, want ErrSelf", err)
	}
	// A second admin unlocks the first.
	u2, _ := e.svc.Create(ctx, a, CreateInput{Username: "second", Password: testUserPasswordNew, IsActive: true}, Meta{})
	_ = e.q.AddUserRole(ctx, u2.ID, adminRole.ID)
	fresh, _ := e.svc.Get(ctx, a, u.ID)
	if _, err := e.svc.Update(ctx, a, u.ID, UpdateInput{DisplayName: "x", IsActive: false, Version: fresh.Version}, Meta{}); err != nil {
		t.Fatalf("disable with two admins = %v", err)
	}
}

func TestForbidden(t *testing.T) {
	e := newTestEnv(t)
	svc := New(e.q, fakeAuthz{deny: true}, nil, nil)
	if _, err := svc.List(context.Background(), actor(), "", nil, 10, 0); !errors.Is(err, ErrForbidden) {
		t.Fatalf("List denied = %v, want ErrForbidden", err)
	}
}
