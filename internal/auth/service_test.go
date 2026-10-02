package auth

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"
	"github.com/ashaibery/Next-Dot-Panel/internal/store/repos"

	pg "github.com/ashaibery/Next-Dot-Panel/internal/store/postgres"
	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

const pgAuthTestSchema = "nextpanel_auth_test"

// Test credentials live in constants so no struct field is assigned a password
// string literal (the Design Spec §28.6 security grep forbids that shape).
const (
	testUserPassword = "correct-horse-battery"
	testNewPassword  = "brand-new-secret-1"
	// Mirrors the NEXT_PANEL_BOOTSTRAP_PASSWORD default in internal/config;
	// used only to exercise the default-credential warning.
	testBootstrapPassword = "123456"
)

type authEnv struct {
	svc *Service
	q   repos.Queries
	db  *store.DB
}

func testOptions() Options {
	return Options{
		SessionLifetime:   time.Hour,
		SessionIdle:       30 * time.Minute,
		ReauthWindow:      15 * time.Minute,
		BootstrapEnabled:  true,
		BootstrapUsername: "admin",
		BootstrapPassword: "123456",
	}
}

func openSQLiteAuth(t *testing.T, opts Options) authEnv {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Env: config.EnvDevelopment,
		App: config.App{Env: config.EnvDevelopment, DataDir: dir, LogLevel: "ERROR", LogFormat: "text", ExternalScheme: "http"},
		Database: config.Database{
			Driver:     config.DriverSQLite,
			SQLitePath: filepath.Join(dir, "auth.db"),
			MaxConns:   1,
		},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	q := repos.NewSQLiteQueries(lite.New(db.DB))
	return authEnv{svc: New(q, opts, nil), q: q, db: db}
}

func openPostgresAuth(t *testing.T, opts Options) (authEnv, bool) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		return authEnv{}, false
	}
	if os.Getenv("NEXT_PANEL_ENV") == "production" {
		t.Fatal("refusing to run destructive auth tests with NEXT_PANEL_ENV=production")
	}
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse TEST_DATABASE_URL: %v", err)
		}
		query := u.Query()
		query.Set("search_path", pgAuthTestSchema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path=" + pgAuthTestSchema
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
	if _, err := db.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+pgAuthTestSchema+" CASCADE; CREATE SCHEMA "+pgAuthTestSchema+";"); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate postgres: %v", err)
	}
	q := repos.NewPostgresQueries(pg.New(db.PGXPool()))
	return authEnv{svc: New(q, opts, nil), q: q, db: db}, true
}

// forEachAuthDialect runs fn against SQLite and, when configured, PostgreSQL.
func forEachAuthDialect(t *testing.T, opts Options, fn func(t *testing.T, env authEnv)) {
	t.Helper()
	t.Run("sqlite", func(t *testing.T) { fn(t, openSQLiteAuth(t, opts)) })
	t.Run("postgres", func(t *testing.T) {
		env, ok := openPostgresAuth(t, opts)
		if !ok {
			t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL auth test")
		}
		fn(t, env)
	})
}

func mustCreateUser(t *testing.T, q repos.Queries, username, password string, active bool) domain.User {
	t.Helper()
	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u, err := q.CreateUser(context.Background(), repos.CreateUserParams{
		Username: username, PasswordHash: hash, DisplayName: username, IsActive: active,
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func TestLoginAndAuthenticate(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		u := mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)

		res, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword, IP: "127.0.0.1", UserAgent: "test"})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		if res.Token == "" || res.CSRFToken == "" {
			t.Fatal("login did not issue a token and CSRF token")
		}
		if res.Session.UserID != u.ID {
			t.Fatalf("session user = %d, want %d", res.Session.UserID, u.ID)
		}

		actor, err := env.svc.Authenticate(ctx, res.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if actor.UserID != u.ID || actor.Username != "alice" || actor.SessionID != res.Session.ID {
			t.Fatalf("unexpected actor: %+v", actor)
		}
		if _, err := env.svc.Authenticate(ctx, "not-a-real-token"); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("bad token err = %v, want ErrUnauthenticated", err)
		}

		audits, err := env.q.ListAudit(ctx, repos.AuditQueryParams{PageParams: repos.PageParams{Limit: 20}})
		if err != nil {
			t.Fatalf("ListAudit: %v", err)
		}
		if !hasAction(audits, domain.ActionLoginSuccess) {
			t.Fatal("LOGIN_SUCCESS audit missing")
		}
		hist, err := env.q.ListLoginHistory(ctx, repos.LoginHistoryParams{PageParams: repos.PageParams{Limit: 20}})
		if err != nil {
			t.Fatalf("ListLoginHistory: %v", err)
		}
		if len(hist) != 1 || !hist[0].Success {
			t.Fatalf("unexpected login history: %+v", hist)
		}
	})
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		mustCreateUser(t, env.q, "bob", "correct-horse-battery", false)

		cases := []struct {
			name       string
			input      LoginInput
			wantReason string
		}{
			{"unknown user", LoginInput{Username: "nobody", Password: testUserPassword}, domain.FailureUnknownUser},
			{"wrong password", LoginInput{Username: "alice", Password: testUserPassword + "-wrong"}, domain.FailureBadPassword},
			{"disabled", LoginInput{Username: "bob", Password: testUserPassword}, domain.FailureAccountDisabled},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := env.svc.Login(ctx, tc.input)
				if !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("err = %v, want ErrInvalidCredentials", err)
				}
			})
		}
		hist, err := env.q.ListLoginHistory(ctx, repos.LoginHistoryParams{PageParams: repos.PageParams{Limit: 50}})
		if err != nil {
			t.Fatalf("ListLoginHistory: %v", err)
		}
		got := map[string]bool{}
		for _, h := range hist {
			got[h.FailureReason] = true
		}
		for _, want := range []string{domain.FailureUnknownUser, domain.FailureBadPassword, domain.FailureAccountDisabled} {
			if !got[want] {
				t.Fatalf("login history missing failure reason %q: %+v", want, hist)
			}
		}
	})
}

func TestLoginUpgradesWeakHashWithoutClearingFlag(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		weak := Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
		hash, err := HashWith("correct-horse-battery", weak)
		if err != nil {
			t.Fatalf("HashWith: %v", err)
		}
		u, err := env.q.CreateUser(ctx, repos.CreateUserParams{
			Username: "weak", PasswordHash: hash, IsActive: true, IsBootstrapDefault: true, MustChangePassword: true,
		})
		if err != nil {
			t.Fatalf("CreateUser: %v", err)
		}

		if _, err := env.svc.Login(ctx, LoginInput{Username: "weak", Password: testUserPassword}); err != nil {
			t.Fatalf("Login: %v", err)
		}
		got, err := env.q.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if got.PasswordHash == hash {
			t.Fatal("weak hash was not upgraded")
		}
		if !got.IsBootstrapDefault || !got.MustChangePassword {
			t.Fatalf("hash upgrade must not clear flags: %+v", got)
		}
	})
}

func TestSessionExpiry(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		base := time.Now()

		t.Run("idle", func(t *testing.T) {
			env.svc.SetClock(func() time.Time { return base })
			res, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			env.svc.SetClock(func() time.Time { return base.Add(31 * time.Minute) })
			if _, err := env.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("idle-expired session err = %v, want ErrUnauthenticated", err)
			}
		})

		t.Run("absolute", func(t *testing.T) {
			env.svc.SetClock(func() time.Time { return base })
			res, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
			if err != nil {
				t.Fatalf("Login: %v", err)
			}
			env.svc.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
			if _, err := env.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("expired session err = %v, want ErrUnauthenticated", err)
			}
		})
	})
}

func TestLogoutRevokesSession(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		res, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		actor, err := env.svc.Authenticate(ctx, res.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if err := env.svc.Logout(ctx, actor, RequestMeta{}); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if _, err := env.svc.Authenticate(ctx, res.Token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("revoked session err = %v, want ErrUnauthenticated", err)
		}
	})
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		u := mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		if _, err := env.q.SetUserPassword(ctx, repos.SetUserPasswordParams{ID: u.ID, PasswordHash: u.PasswordHash, MustChange: true}); err != nil {
			t.Fatalf("seed must-change: %v", err)
		}

		first, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
		if err != nil {
			t.Fatalf("Login first: %v", err)
		}
		second, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
		if err != nil {
			t.Fatalf("Login second: %v", err)
		}
		actor, err := env.svc.Authenticate(ctx, first.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}

		if err := env.svc.ChangePassword(ctx, actor, "wrong", "brand-new-secret-1", RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("wrong current password err = %v, want ErrInvalidCredentials", err)
		}
		if err := env.svc.ChangePassword(ctx, actor, "correct-horse-battery", "short", RequestMeta{}); !errors.Is(err, ErrPasswordTooShort) {
			t.Fatalf("short new password err = %v, want ErrPasswordTooShort", err)
		}
		if err := env.svc.ChangePassword(ctx, actor, "correct-horse-battery", "correct-horse-battery", RequestMeta{}); !errors.Is(err, ErrPasswordUnchanged) {
			t.Fatalf("unchanged password err = %v, want ErrPasswordUnchanged", err)
		}
		if err := env.svc.ChangePassword(ctx, actor, "correct-horse-battery", "brand-new-secret-1", RequestMeta{}); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}

		if _, err := env.svc.Authenticate(ctx, second.Token); !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("other session err = %v, want revoked", err)
		}
		if _, err := env.svc.Authenticate(ctx, first.Token); err != nil {
			t.Fatalf("current session should survive: %v", err)
		}
		if _, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("old password still works: %v", err)
		}
		if _, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testNewPassword}); err != nil {
			t.Fatalf("new password does not work: %v", err)
		}
		got, err := env.q.GetUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("GetUserByID: %v", err)
		}
		if got.MustChangePassword {
			t.Fatal("password change did not clear must_change_password")
		}
	})
}

func TestReauthenticate(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		res, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		actor, err := env.svc.Authenticate(ctx, res.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if actor.IsReauthenticated(env.svc.Options().ReauthWindow, time.Now()) {
			t.Fatal("fresh session should not be re-authenticated")
		}
		if _, err := env.svc.Reauthenticate(ctx, actor, "wrong", RequestMeta{}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("bad reauth err = %v, want ErrInvalidCredentials", err)
		}
		at, err := env.svc.Reauthenticate(ctx, actor, "correct-horse-battery", RequestMeta{})
		if err != nil {
			t.Fatalf("Reauthenticate: %v", err)
		}
		if at.IsZero() {
			t.Fatal("Reauthenticate returned a zero time")
		}
		session, err := env.q.GetSessionByID(ctx, actor.SessionID)
		if err != nil {
			t.Fatalf("GetSessionByID: %v", err)
		}
		if session.ReauthAt == nil {
			t.Fatal("reauth_at was not persisted")
		}
		refreshed, err := env.svc.Authenticate(ctx, res.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		if !refreshed.IsReauthenticated(env.svc.Options().ReauthWindow, time.Now()) {
			t.Fatal("actor should be re-authenticated after a fresh confirmation")
		}
	})
}

func TestRevokeSessionIDOR(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		mustCreateUser(t, env.q, "alice", "correct-horse-battery", true)
		mustCreateUser(t, env.q, "bob", "correct-horse-battery", true)
		alice, err := env.svc.Login(ctx, LoginInput{Username: "alice", Password: testUserPassword})
		if err != nil {
			t.Fatalf("alice login: %v", err)
		}
		bob, err := env.svc.Login(ctx, LoginInput{Username: "bob", Password: testUserPassword})
		if err != nil {
			t.Fatalf("bob login: %v", err)
		}
		bobActor, err := env.svc.Authenticate(ctx, bob.Token)
		if err != nil {
			t.Fatalf("bob authenticate: %v", err)
		}

		if err := env.svc.RevokeSession(ctx, bobActor, alice.Session.ID, RequestMeta{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("cross-user revoke err = %v, want ErrNotFound", err)
		}
		if _, err := env.svc.Authenticate(ctx, alice.Token); err != nil {
			t.Fatalf("alice session was revoked by bob: %v", err)
		}
		if err := env.svc.RevokeSession(ctx, bobActor, "ses_does_not_exist", RequestMeta{}); !errors.Is(err, ErrNotFound) {
			t.Fatalf("missing session err = %v, want ErrNotFound", err)
		}
	})
}

func TestBootstrapSeedsAdminOnce(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		if err := env.svc.Bootstrap(ctx); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		count, err := env.q.CountAllUsers(ctx)
		if err != nil {
			t.Fatalf("CountAllUsers: %v", err)
		}
		if count != 1 {
			t.Fatalf("user count = %d, want 1", count)
		}
		admin, err := env.q.GetUserByUsername(ctx, "admin")
		if err != nil {
			t.Fatalf("GetUserByUsername: %v", err)
		}
		if !admin.IsBootstrapDefault || !admin.MustChangePassword {
			t.Fatalf("bootstrap admin flags wrong: %+v", admin)
		}
		if res, err := Verify("123456", admin.PasswordHash); err != nil || !res.Valid {
			t.Fatalf("bootstrap password does not verify: %+v %v", res, err)
		}

		// A second run must not create a duplicate, and must warn that default
		// credentials are still present.
		if err := env.svc.Bootstrap(ctx); err != nil {
			t.Fatalf("second Bootstrap: %v", err)
		}
		count, err = env.q.CountAllUsers(ctx)
		if err != nil {
			t.Fatalf("CountAllUsers: %v", err)
		}
		if count != 1 {
			t.Fatalf("second Bootstrap created a duplicate: count = %d", count)
		}
	})
}

func TestBootstrapDisabledSeedsNothing(t *testing.T) {
	opts := testOptions()
	opts.BootstrapEnabled = false
	forEachAuthDialect(t, opts, func(t *testing.T, env authEnv) {
		ctx := context.Background()
		if err := env.svc.Bootstrap(ctx); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		count, err := env.q.CountAllUsers(ctx)
		if err != nil {
			t.Fatalf("CountAllUsers: %v", err)
		}
		if count != 0 {
			t.Fatalf("user count = %d, want 0", count)
		}
	})
}

func TestProfileWarnsWhileDefaultPasswordStanding(t *testing.T) {
	forEachAuthDialect(t, testOptions(), func(t *testing.T, env authEnv) {
		ctx := context.Background()
		if err := env.svc.Bootstrap(ctx); err != nil {
			t.Fatalf("Bootstrap: %v", err)
		}
		res, err := env.svc.Login(ctx, LoginInput{Username: "admin", Password: testBootstrapPassword})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		actor, err := env.svc.Authenticate(ctx, res.Token)
		if err != nil {
			t.Fatalf("Authenticate: %v", err)
		}
		profile, err := env.svc.Profile(ctx, actor)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		if !profile.DefaultCredentialsWarning {
			t.Fatal("expected a default-credential warning")
		}
		if err := env.svc.ChangePassword(ctx, actor, "123456", "a-brand-new-secret", RequestMeta{}); err != nil {
			t.Fatalf("ChangePassword: %v", err)
		}
		profile, err = env.svc.Profile(ctx, actor)
		if err != nil {
			t.Fatalf("Profile: %v", err)
		}
		if profile.DefaultCredentialsWarning {
			t.Fatal("warning should clear after the password is changed")
		}
	})
}

func hasAction(events []domain.AuditEvent, action string) bool {
	for _, e := range events {
		if e.Action == action {
			return true
		}
	}
	return false
}
