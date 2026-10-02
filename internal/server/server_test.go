package server

import (
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/credentials"
	"github.com/ashaibery/Next-Dot-Panel/internal/crypto"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
	"github.com/ashaibery/Next-Dot-Panel/internal/secret"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

type fakeProvider struct {
	mu         sync.Mutex
	status     provider.ConnectionStatus
	connectErr error
	pingErr    error
	latency    time.Duration
	execOut    []byte
	execCode   int
	execErr    error
}

func (f *fakeProvider) ID() string { return "fake" }

func (f *fakeProvider) Connect(context.Context, domain.Target, provider.CredentialSource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.connectErr != nil {
		f.status = provider.StatusFailed
		return f.connectErr
	}
	f.status = provider.StatusConnected
	return nil
}

func (f *fakeProvider) Disconnect(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = provider.StatusDisconnected
	return nil
}

func (f *fakeProvider) Status() provider.ConnectionStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *fakeProvider) Ping(context.Context) (time.Duration, error) {
	return f.latency, f.pingErr
}

func (f *fakeProvider) Exec(context.Context, provider.Command) (*provider.ExecResult, error) {
	return &provider.ExecResult{ExitCode: f.execCode, Stdout: f.execOut}, f.execErr
}

func (f *fakeProvider) ExecStream(context.Context, provider.Command) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

type testEnv struct {
	svc   *Service
	q     repos.Queries
	rbac  *rbac.Service
	fake  *fakeProvider
	reg   *provider.Registry
	actor auth.Actor
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dir, "server.db"), MaxConns: 1},
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
	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewEncryptor(key, 1, nil)
	rbacSvc := rbac.New(q, audit.New(q, nil), nil)
	if err := rbacSvc.Seed(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fake := &fakeProvider{latency: 5 * time.Millisecond, execOut: []byte("Linux 5.15.0-generic x86_64\n")}
	reg := provider.NewRegistry(nil)
	reg.Register(domain.TargetSSH, func() provider.ServerExecutionProvider { return fake })

	svc := New(q, credentials.New(q, enc), rbacSvc, reg, audit.New(q, nil), nil, Options{})
	admin := createUser(t, q, "admin")
	assignAdmin(t, q, admin)
	return &testEnv{
		svc: svc, q: q, rbac: rbacSvc, fake: fake, reg: reg,
		actor: auth.Actor{UserID: admin.ID, Username: admin.Username, SessionID: "ses_test", Permissions: domain.AllPermissions()},
	}
}

func createUser(t *testing.T, q repos.Queries, name string) domain.User {
	t.Helper()
	u, err := q.CreateUser(context.Background(), repos.CreateUserParams{
		Username: name, PasswordHash: "argon2id$fake", IsActive: true,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func assignAdmin(t *testing.T, q repos.Queries, u domain.User) {
	t.Helper()
	role, err := q.GetRoleByName(context.Background(), domain.RoleAdmin)
	if err != nil {
		t.Fatalf("admin role: %v", err)
	}
	if err := q.AddUserRole(context.Background(), u.ID, role.ID); err != nil {
		t.Fatalf("assign admin: %v", err)
	}
}

func createInput(name string) CreateInput {
	return CreateInput{
		Name: name, TargetType: domain.TargetSSH, Host: "10.0.0.1", Port: 22, Username: "root",
		AuthMethod: domain.AuthPassword, HostKeyPolicy: domain.HostKeyTOFU,
		Credential: credentials.Material{Password: secret.New("hunter2")},
	}
}

func TestCreateRequiresPermission(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	weak := auth.Actor{UserID: e.actor.UserID, Username: "weak", SessionID: "ses"}
	if _, err := e.svc.Create(ctx, weak, createInput("nope"), Meta{}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("Create without permission = %v, want ErrForbidden", err)
	}
}

func TestCreateGetUpdateDelete(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	srv, err := e.svc.Create(ctx, e.actor, createInput("web1"), Meta{})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if srv.Name != "web1" || srv.Status != domain.StatusUnknown {
		t.Fatalf("unexpected server: %+v", srv)
	}
	u, err := e.svc.creds.Unwrap(ctx, srv.ID)
	if err != nil || u.Password().Reveal() != "hunter2" {
		t.Fatalf("credential not stored: %v", err)
	}
	u.Close()

	got, err := e.svc.Get(ctx, e.actor, srv.ID)
	if err != nil || got.ID != srv.ID {
		t.Fatalf("Get: %v %+v", err, got)
	}

	upd := UpdateInput{
		Name: "web1-renamed", Host: "10.0.0.2", Port: 2222, Username: "deploy",
		AuthMethod: domain.AuthPassword, HostKeyPolicy: domain.HostKeyStrict,
		Tags: []string{"prod"}, Version: srv.Version,
		Credential: credentials.Material{Password: secret.New("rotated")},
	}
	updated, err := e.svc.Update(ctx, e.actor, srv.ID, upd, Meta{})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != "web1-renamed" || updated.Target.Port != 2222 {
		t.Fatalf("update not applied: %+v", updated)
	}
	u2, _ := e.svc.creds.Unwrap(ctx, srv.ID)
	if u2.Password().Reveal() != "rotated" {
		t.Fatal("credential was not rotated")
	}
	u2.Close()

	if err := e.svc.Delete(ctx, e.actor, srv.ID, Meta{}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := e.svc.Get(ctx, e.actor, srv.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
}

func TestCreateValidation(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()

	cases := []struct {
		name string
		mut  func(*CreateInput)
		want error
	}{
		{"missing host", func(in *CreateInput) { in.Host = "" }, ErrInvalid},
		{"bad port", func(in *CreateInput) { in.Port = 70000 }, ErrInvalid},
		{"missing username", func(in *CreateInput) { in.Username = "" }, ErrInvalid},
		{"bad auth", func(in *CreateInput) { in.AuthMethod = "magic" }, ErrInvalid},
		{"bad policy", func(in *CreateInput) { in.HostKeyPolicy = "LAX" }, ErrInvalid},
		{"key auth without key", func(in *CreateInput) {
			in.AuthMethod = domain.AuthKey
			in.Credential = credentials.Material{}
		}, ErrNoCred},
		{"local disabled", func(in *CreateInput) { in.TargetType = domain.TargetLocal }, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := createInput("bad-" + strings.ReplaceAll(tc.name, " ", "-"))
			tc.mut(&in)
			if _, err := e.svc.Create(ctx, e.actor, in, Meta{}); !errors.Is(err, tc.want) {
				t.Fatalf("Create = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDuplicateNameConflicts(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Create(ctx, e.actor, createInput("dup"), Meta{}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := e.svc.Create(ctx, e.actor, createInput("dup"), Meta{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate Create = %v, want ErrConflict", err)
	}
}

func TestOptimisticLock(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("lock"), Meta{})
	stale := UpdateInput{
		Name: srv.Name, Host: srv.Target.Host, Port: srv.Target.Port, Username: srv.Target.Username,
		AuthMethod: domain.AuthPassword, HostKeyPolicy: domain.HostKeyTOFU, Version: srv.Version + 99,
	}
	if _, err := e.svc.Update(ctx, e.actor, srv.ID, stale, Meta{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Update = %v, want ErrConflict", err)
	}
}

func TestVisibilityAndIDOR(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("secret"), Meta{})

	other := createUser(t, e.q, "other")
	stranger := auth.Actor{UserID: other.ID, Username: other.Username, SessionID: "ses"}
	if _, err := e.svc.Get(ctx, stranger, srv.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger Get = %v, want ErrNotFound (not 403)", err)
	}
	if _, err := e.svc.Update(ctx, stranger, srv.ID, UpdateInput{Name: "x", Version: srv.Version}, Meta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger Update = %v, want ErrNotFound", err)
	}
	if err := e.svc.Delete(ctx, stranger, srv.ID, Meta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stranger Delete = %v, want ErrNotFound", err)
	}

	// A per-server grant makes the server visible and connectable.
	if err := e.q.GrantServerPermission(ctx, repos.GrantServerPermissionParams{
		UserID: other.ID, ServerID: srv.ID, Permission: domain.PermServersConnect,
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}
	granted := auth.Actor{UserID: other.ID, Username: other.Username, SessionID: "ses", Permissions: nil}
	if _, err := e.svc.Get(ctx, granted, srv.ID); err != nil {
		t.Fatalf("granted Get = %v, want nil", err)
	}
	if _, err := e.svc.TestConnection(ctx, granted, srv.ID, Meta{}); err != nil {
		t.Fatalf("granted TestConnection = %v, want nil", err)
	}
}

func TestListFiltersByVisibility(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv1, _ := e.svc.Create(ctx, e.actor, createInput("s1"), Meta{})
	_, _ = e.svc.Create(ctx, e.actor, createInput("s2"), Meta{})

	other := createUser(t, e.q, "other")
	_ = e.q.GrantServerPermission(ctx, repos.GrantServerPermissionParams{
		UserID: other.ID, ServerID: srv1.ID, Permission: domain.PermServersRead,
	})
	granted := auth.Actor{UserID: other.ID, Username: other.Username, SessionID: "ses"}
	page, err := e.svc.List(ctx, granted, Filter{}, domain.Page{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if page.Total != 1 || len(page.Items) != 1 || page.Items[0].ID != srv1.ID {
		t.Fatalf("visible list = %+v, want only %d", page, srv1.ID)
	}
	adminPage, _ := e.svc.List(ctx, e.actor, Filter{}, domain.Page{})
	if adminPage.Total != 2 {
		t.Fatalf("admin list total = %d, want 2", adminPage.Total)
	}
}

func TestTestConnectionSuccessRecordsSystemInfo(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("online"), Meta{})

	res, err := e.svc.TestConnection(ctx, e.actor, srv.ID, Meta{})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if res.Status != domain.StatusOnline {
		t.Fatalf("status = %s, want ONLINE", res.Status)
	}
	got, _ := e.svc.Get(ctx, e.actor, srv.ID)
	if got.Status != domain.StatusOnline || got.OS != "Linux" || got.Kernel != "5.15.0-generic" || got.Arch != "x86_64" {
		t.Fatalf("system info not recorded: %+v", got)
	}
}

func TestTestConnectionHostKeyUnknownIsNotAutoTrusted(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("unknownkey"), Meta{})

	e.fake.connectErr = &provider.HostKeyError{
		Code: provider.CodeHostKeyUnknown, Host: srv.Target.Host,
		Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc", PublicKey: []byte("key"),
	}
	res, err := e.svc.TestConnection(ctx, e.actor, srv.ID, Meta{})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if res.Status != domain.StatusError || res.HostKey == nil || res.HostKey.Fingerprint != "SHA256:abc" {
		t.Fatalf("expected a host-key prompt, got %+v", res)
	}
	// Nothing was pinned by the failed connection.
	keys, _ := e.svc.ListHostKeys(ctx, e.actor, srv.ID)
	if len(keys) != 0 {
		t.Fatalf("host key was pinned without consent: %+v", keys)
	}

	// Explicit trust pins it and requires the hostkey permission.
	if err := e.svc.TrustHostKey(ctx, e.actor, srv.ID, res.HostKey.Algorithm, res.HostKey.Fingerprint, res.HostKey.PublicKey, Meta{}); err != nil {
		t.Fatalf("TrustHostKey: %v", err)
	}
	keys, _ = e.svc.ListHostKeys(ctx, e.actor, srv.ID)
	if len(keys) != 1 || keys[0].State != domain.HostKeyTrusted {
		t.Fatalf("host key not pinned: %+v", keys)
	}
}

func TestTrustHostKeyRequiresPermission(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("trustperm"), Meta{})
	other := createUser(t, e.q, "other")
	stranger := auth.Actor{UserID: other.ID, Username: other.Username, SessionID: "ses"}
	if err := e.svc.TrustHostKey(ctx, stranger, srv.ID, "ssh-ed25519", "SHA256:abc", []byte("key"), Meta{}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("TrustHostKey without permission = %v, want ErrNotFound", err)
	}
}

func TestTestConnectionAuthFailure(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("authfail"), Meta{})
	e.fake.connectErr = provider.NewError(provider.CodeAuthentication, "connect", errors.New("denied"))

	res, err := e.svc.TestConnection(ctx, e.actor, srv.ID, Meta{})
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if res.Status != domain.StatusError || res.Detail != string(provider.CodeAuthentication) {
		t.Fatalf("result = %+v, want ERROR/%s", res, provider.CodeAuthentication)
	}
}

func TestListHostKeys(t *testing.T) {
	e := newTestEnv(t)
	ctx := context.Background()
	srv, _ := e.svc.Create(ctx, e.actor, createInput("hk"), Meta{})
	if err := e.svc.TrustHostKey(ctx, e.actor, srv.ID, "ssh-ed25519", "SHA256:xyz", []byte("pub"), Meta{}); err != nil {
		t.Fatalf("TrustHostKey: %v", err)
	}
	keys, err := e.svc.ListHostKeys(ctx, e.actor, srv.ID)
	if err != nil || len(keys) != 1 || keys[0].Fingerprint != "SHA256:xyz" {
		t.Fatalf("ListHostKeys = %+v %v", keys, err)
	}
}
