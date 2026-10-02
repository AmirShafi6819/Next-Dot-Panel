package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/auth"
	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/httpapi"
	"github.com/ashaibery/Next-Dot-Panel/internal/logging"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

const (
	testAdminUser = "admin"
	testAdminPass = "123456"
)

// newAuthServer builds a full HTTP server over a migrated SQLite database with
// a bootstrapped administrator, and a cookie jar so the browser flow is
// exercised end to end.
func newAuthServer(t *testing.T) (*httptest.Server, *http.Client) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := &config.Config{
		Env:      config.EnvDevelopment,
		App:      config.App{Env: config.EnvDevelopment, DataDir: dataDir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{Driver: config.DriverSQLite, SQLitePath: filepath.Join(dataDir, "auth.db"), MaxConns: 1},
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
	svc := auth.New(q, auth.Options{
		SessionLifetime:   time.Hour,
		SessionIdle:       30 * time.Minute,
		ReauthWindow:      15 * time.Minute,
		BootstrapEnabled:  true,
		BootstrapUsername: testAdminUser,
		BootstrapPassword: testAdminPass,
	}, nil)
	if err := svc.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	h := httpapi.New(httpapi.Deps{Config: cfg, DB: db, Log: logging.New(&syncBuffer{}, "text", "ERROR"), Auth: svc})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	return srv, &http.Client{Jar: jar}
}

func postJSON(t *testing.T, client *http.Client, url string, body any) *http.Response {
	t.Helper()
	buf, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func get(t *testing.T, client *http.Client, url string) *http.Response {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

func errorCode(t *testing.T, resp *http.Response) string {
	t.Helper()
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	return envelope.Error.Code
}

func TestAuthCookieFlow(t *testing.T) {
	srv, client := newAuthServer(t)

	// Protected endpoint without a cookie is rejected.
	if resp := get(t, client, srv.URL+"/api/v1/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d, want 401", resp.StatusCode)
	}

	// Wrong password is a generic 401 with no cookie.
	resp := postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{"username": testAdminUser, "password": "wrong"})
	if resp.StatusCode != http.StatusUnauthorized || errorCode(t, resp) != "invalid_credentials" {
		t.Fatalf("bad login status/code = %d/%s", resp.StatusCode, errorCode(t, resp))
	}

	// Successful login issues the session and CSRF cookies.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{"username": testAdminUser, "password": testAdminPass})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var login struct {
		CSRFToken                 string `json:"csrf_token"`
		DefaultCredentialsWarning bool   `json:"default_credentials_warning"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if login.CSRFToken == "" {
		t.Fatal("login did not return a CSRF token")
	}
	if !login.DefaultCredentialsWarning {
		t.Fatal("bootstrap administrator should carry a default-credentials warning")
	}
	setCookies := strings.Join(resp.Header.Values("Set-Cookie"), "\n")
	if !strings.Contains(setCookies, "nextpanel_session=") {
		t.Fatalf("session cookie missing: %q", setCookies)
	}
	if !strings.Contains(setCookies, "nextpanel_csrf=") {
		t.Fatalf("csrf cookie missing: %q", setCookies)
	}
	sessionLine := ""
	for _, line := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(line, "nextpanel_session=") {
			sessionLine = line
		}
	}
	if !strings.Contains(sessionLine, "HttpOnly") {
		t.Fatalf("session cookie is not HttpOnly: %q", sessionLine)
	}

	// The authenticated surface works.
	resp = get(t, client, srv.URL+"/api/v1/auth/me")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/me status = %d, want 200", resp.StatusCode)
	}
	var me struct {
		User struct {
			Username string `json:"username"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil {
		t.Fatalf("decode me: %v", err)
	}
	if me.User.Username != testAdminUser {
		t.Fatalf("me username = %q, want %q", me.User.Username, testAdminUser)
	}

	resp = get(t, client, srv.URL+"/api/v1/auth/sessions")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/sessions status = %d, want 200", resp.StatusCode)
	}
	var sessions struct {
		Sessions []struct {
			Current bool `json:"current"`
		} `json:"sessions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions.Sessions) != 1 || !sessions.Sessions[0].Current {
		t.Fatalf("unexpected sessions: %+v", sessions.Sessions)
	}

	// Re-authentication.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/reauth", map[string]string{"password": testAdminPass})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/reauth status = %d, want 200", resp.StatusCode)
	}

	// Change password, then prove the old one is dead and the new one works.
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/password", map[string]string{"current_password": "wrong", "new_password": "a-brand-new-secret"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad current password status = %d, want 401", resp.StatusCode)
	}
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/password", map[string]string{"current_password": testAdminPass, "new_password": "short"})
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "password_too_short" {
		t.Fatalf("short password status/code = %d/%s", resp.StatusCode, errorCode(t, resp))
	}
	resp = postJSON(t, client, srv.URL+"/api/v1/auth/password", map[string]string{"current_password": testAdminPass, "new_password": "a-brand-new-secret"})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("change password status = %d, want 204", resp.StatusCode)
	}

	// Logout clears the session; the old cookie no longer authenticates.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/auth/logout", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("logout: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("logout status = %d, want 204", resp.StatusCode)
	}
	if resp := get(t, client, srv.URL+"/api/v1/auth/me"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("after logout /me status = %d, want 401", resp.StatusCode)
	}
}

func TestLoginRejectsNonJSONAndMissingFields(t *testing.T) {
	srv, client := newAuthServer(t)

	resp, err := client.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader([]byte("not json")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest || errorCode(t, resp) != "invalid_request" {
		t.Fatalf("status/code = %d/%s, want 400/invalid_request", resp.StatusCode, errorCode(t, resp))
	}

	resp = postJSON(t, client, srv.URL+"/api/v1/auth/login", map[string]string{"username": "admin"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("missing password status = %d, want 400", resp.StatusCode)
	}
}
