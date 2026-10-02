package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/audit"
	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/rbac"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

// newFullServer builds a server with authentication and RBAC mounted and the
// permission catalogue seeded, returning the query surface so tests can create
// users and assign roles directly.
func newFullServer(t *testing.T) (*httptest.Server, *http.Client, repos.Queries, *rbac.Service) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dataDir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dataDir, "full.db"), MaxConns: 1},
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
	rbacSvc := rbac.New(q, audit.New(q, log), log)
	if err := rbacSvc.Seed(ctx); err != nil {
		t.Fatalf("rbac seed: %v", err)
	}
	if err := rbacSvc.EnsureBootstrapAdminRole(ctx, testAdminUser); err != nil {
		t.Fatalf("bootstrap admin role: %v", err)
	}

	h := httpapi.New(httpapi.Deps{Config: cfg, DB: db, Log: log, Auth: authSvc, RBAC: rbacSvc})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return srv, &http.Client{Jar: jar}, q, rbacSvc
}

func login(t *testing.T, client *http.Client, base, username, password string) {
	t.Helper()
	resp := postJSON(t, client, base+"/api/v1/auth/login", map[string]string{"username": username, "password": password})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s status = %d", username, resp.StatusCode)
	}
}

func TestRBACEndpointsEnforcePermissions(t *testing.T) {
	srv, adminClient, q, _ := newFullServer(t)
	ctx := context.Background()

	// Unauthenticated.
	resp := get(t, adminClient, srv.URL+"/api/v1/roles")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /roles status = %d, want 401", resp.StatusCode)
	}

	login(t, adminClient, srv.URL, testAdminUser, testAdminPass)

	// The bootstrap administrator holds the admin role, so it can read roles.
	resp = get(t, adminClient, srv.URL+"/api/v1/roles")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("admin /roles status = %d, want 200", resp.StatusCode)
	}
	var roles struct {
		Roles []struct {
			Name        string   `json:"name"`
			IsSystem    bool     `json:"is_system"`
			Permissions []string `json:"permissions"`
		} `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&roles); err != nil {
		t.Fatalf("decode roles: %v", err)
	}
	names := map[string]bool{}
	for _, r := range roles.Roles {
		names[r.Name] = true
	}
	if !names["admin"] || !names["operator"] || !names["viewer"] {
		t.Fatalf("seeded roles missing: %+v", names)
	}

	// Create a custom role.
	resp = postJSON(t, adminClient, srv.URL+"/api/v1/roles", map[string]any{
		"name": "auditor", "description": "reads audit", "permissions": []string{"audit.read"},
	})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create role status = %d, want 201", resp.StatusCode)
	}

	// A viewer cannot read roles or create them.
	hash, err := auth.Hash("viewer-password-1")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	viewer, err := q.CreateUser(ctx, repos.CreateUserParams{Username: "vicky", PasswordHash: hash, IsActive: true})
	if err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	viewerRole, err := q.GetRoleByName(ctx, domain.RoleViewer)
	if err != nil {
		t.Fatalf("viewer role: %v", err)
	}
	if err := q.AddUserRole(ctx, viewer.ID, viewerRole.ID); err != nil {
		t.Fatalf("assign viewer: %v", err)
	}
	jar, _ := cookiejar.New(nil)
	viewerClient := &http.Client{Jar: jar}
	login(t, viewerClient, srv.URL, "vicky", "viewer-password-1")

	if resp := get(t, viewerClient, srv.URL+"/api/v1/roles"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer /roles status = %d, want 403", resp.StatusCode)
	}
	resp = postJSON(t, viewerClient, srv.URL+"/api/v1/roles", map[string]any{"name": "sneaky"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer create role status = %d, want 403", resp.StatusCode)
	}
	if resp := get(t, viewerClient, srv.URL+"/api/v1/permissions"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer /permissions status = %d, want 403", resp.StatusCode)
	}

	// The denial is audited.
	action := domain.ActionAccessDenied
	events, err := q.ListAudit(ctx, repos.AuditQueryParams{Action: &action, PageParams: repos.PageParams{Limit: 20}})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("authorization denial was not audited")
	}
}

func TestRBACSystemRoleIsProtectedOverHTTP(t *testing.T) {
	srv, client, q, _ := newFullServer(t)
	ctx := context.Background()
	login(t, client, srv.URL, testAdminUser, testAdminPass)

	admin, err := q.GetRoleByName(ctx, domain.RoleAdmin)
	if err != nil {
		t.Fatalf("admin role: %v", err)
	}
	req, _ := http.NewRequest(http.MethodPatch, srv.URL+"/api/v1/roles/"+strconv.FormatInt(int64(admin.ID), 10), jsonBody(map[string]any{"name": "admin"}))
	req.Header.Set("Content-Type", "application/json")
	patched, err := client.Do(req)
	if err != nil {
		t.Fatalf("patch: %v", err)
	}
	defer func() { _ = patched.Body.Close() }()
	if patched.StatusCode != http.StatusConflict {
		t.Fatalf("edit system role status = %d, want 409", patched.StatusCode)
	}
}

func jsonBody(v any) *bytes.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}
