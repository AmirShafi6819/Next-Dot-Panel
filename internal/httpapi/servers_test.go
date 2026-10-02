package httpapi_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/credentials"
	"github.com/ashaibery/Next-Dot-Panel/internal/crypto"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/provider"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
	"github.com/ashaibery/Next-Dot-Panel/internal/server"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

type httpFakeProvider struct{}

func (httpFakeProvider) ID() string { return "fake" }
func (httpFakeProvider) Connect(context.Context, domain.Target, provider.CredentialSource) error {
	return nil
}
func (httpFakeProvider) Disconnect(context.Context) error  { return nil }
func (httpFakeProvider) Status() provider.ConnectionStatus { return provider.StatusConnected }
func (httpFakeProvider) Ping(context.Context) (time.Duration, error) {
	return 3 * time.Millisecond, nil
}
func (httpFakeProvider) Exec(context.Context, provider.Command) (*provider.ExecResult, error) {
	return &provider.ExecResult{ExitCode: 0, Stdout: []byte("Linux 5.15.0 x86_64\n")}, nil
}
func (httpFakeProvider) ExecStream(context.Context, provider.Command) (io.ReadCloser, error) {
	return io.NopCloser(nil), nil
}

func (httpFakeProvider) OpenPTY(context.Context, provider.PTYOptions) (provider.PTY, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "pty", nil)
}
func (httpFakeProvider) Stat(context.Context, string) (*domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "stat", nil)
}
func (httpFakeProvider) ListDir(context.Context, string) ([]domain.FileInfo, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "list", nil)
}
func (httpFakeProvider) OpenRead(context.Context, string, int64) (io.ReadCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "read", nil)
}
func (httpFakeProvider) OpenWrite(context.Context, string, os.FileMode, int64) (io.WriteCloser, error) {
	return nil, provider.NewError(provider.CodeUnsupported, "write", nil)
}
func (httpFakeProvider) Remove(context.Context, []string, bool) error {
	return provider.NewError(provider.CodeUnsupported, "remove", nil)
}
func (httpFakeProvider) Rename(context.Context, string, string) error {
	return provider.NewError(provider.CodeUnsupported, "rename", nil)
}
func (httpFakeProvider) Mkdir(context.Context, string, os.FileMode) error {
	return provider.NewError(provider.CodeUnsupported, "mkdir", nil)
}

func newServerEnv(t *testing.T) (*httptest.Server, *http.Client, repos.Queries) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dataDir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dataDir, "srv.db"), MaxConns: 1},
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
	log := logging.New(&syncBuffer{}, "text", "ERROR")

	authSvc := auth.New(q, auth.Options{
		SessionLifetime: time.Hour, SessionIdle: 30 * time.Minute, ReauthWindow: 15 * time.Minute,
		BootstrapEnabled: true, BootstrapUsername: testAdminUser, BootstrapPassword: testAdminPass,
	}, log)
	if err := authSvc.Bootstrap(ctx); err != nil {
		t.Fatalf("auth bootstrap: %v", err)
	}
	auditWriter := audit.New(q, log)
	rbacSvc := rbac.New(q, auditWriter, log)
	if err := rbacSvc.Seed(ctx); err != nil {
		t.Fatalf("rbac seed: %v", err)
	}
	if err := rbacSvc.EnsureBootstrapAdminRole(ctx, testAdminUser); err != nil {
		t.Fatalf("admin role: %v", err)
	}

	key, _ := crypto.GenerateKey()
	enc, _ := crypto.NewEncryptor(key, 1, nil)
	reg := provider.NewRegistry(log)
	reg.Register(domain.TargetSSH, func() provider.ServerExecutionProvider { return httpFakeProvider{} })
	serverSvc := server.New(q, credentials.New(q, enc), rbacSvc, reg, auditWriter, log, server.Options{})

	h := httpapi.New(httpapi.Deps{Config: cfg, DB: db, Log: log, Auth: authSvc, RBAC: rbacSvc, Servers: serverSvc})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, q
}

func TestServerEndpoints(t *testing.T) {
	srv, client, q := newServerEnv(t)
	ctx := context.Background()
	login(t, client, srv.URL, testAdminUser, testAdminPass)

	// Create.
	resp := postJSON(t, client, srv.URL+"/api/v1/servers", map[string]any{
		"name": "web1", "target_type": "ssh", "host": "10.0.0.5", "port": 22, "username": "root",
		"auth_method": "password", "host_key_policy": "TOFU", "password": "hunter2",
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status = %d, want 201", resp.StatusCode)
	}
	var created struct {
		ID      int64  `json:"id"`
		Name    string `json:"name"`
		Version int64  `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	if created.ID == 0 || created.Name != "web1" {
		t.Fatalf("unexpected server: %+v", created)
	}

	// List.
	resp = get(t, client, srv.URL+"/api/v1/servers")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d", resp.StatusCode)
	}
	var list struct {
		Total int64 `json:"total"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&list)
	if list.Total != 1 {
		t.Fatalf("list total = %d, want 1", list.Total)
	}

	// Connection test.
	resp = postJSON(t, client, srv.URL+"/api/v1/servers/"+itoa(created.ID)+"/test", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("test status = %d", resp.StatusCode)
	}
	var test struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&test)
	if test.Status != string(domain.StatusOnline) {
		t.Fatalf("connection status = %q, want ONLINE", test.Status)
	}

	// Stale update conflicts.
	resp = patchJSON(t, client, srv.URL+"/api/v1/servers/"+itoa(created.ID), map[string]any{
		"name": "web1", "host": "10.0.0.5", "port": 22, "username": "root",
		"auth_method": "password", "host_key_policy": "TOFU", "version": created.Version + 5,
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("stale update status = %d, want 409", resp.StatusCode)
	}

	// A user with no grants sees nothing and cannot fetch the server.
	hash, _ := auth.Hash("viewer-password-1")
	viewer, err := q.CreateUser(ctx, repos.CreateUserParams{Username: "vicky", PasswordHash: hash, IsActive: true})
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	_ = viewer

	jar, _ := cookiejar.New(nil)
	viewerClient := &http.Client{Jar: jar}
	login(t, viewerClient, srv.URL, "vicky", "viewer-password-1")

	resp = get(t, viewerClient, srv.URL+"/api/v1/servers")
	var viewerList struct {
		Total int64 `json:"total"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&viewerList)
	if viewerList.Total != 0 {
		t.Fatalf("viewer list total = %d, want 0", viewerList.Total)
	}
	if resp := get(t, viewerClient, srv.URL+"/api/v1/servers/"+itoa(created.ID)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("viewer get status = %d, want 404", resp.StatusCode)
	}

	// Delete.
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/api/v1/servers/"+itoa(created.ID), nil)
	del, err := client.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = del.Body.Close() }()
	if del.StatusCode != http.StatusNoContent {
		t.Fatalf("delete status = %d, want 204", del.StatusCode)
	}
}

func patchJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPatch, url, jsonBody(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("PATCH %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
