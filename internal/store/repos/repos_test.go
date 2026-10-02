package repos

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
	"github.com/ashaibery/Next-Dot-Panel/internal/store"

	pg "github.com/ashaibery/Next-Dot-Panel/internal/store/postgres"
	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

// openSQLite opens a migrated SQLite database for adapter tests.
func openSQLite(t *testing.T) (*store.DB, Queries) {
	t.Helper()
	cfg := &config.Config{
		Env: config.EnvDevelopment,
		App: config.App{
			Env:            config.EnvDevelopment,
			DataDir:        t.TempDir(),
			LogLevel:       "ERROR",
			LogFormat:      "text",
			ExternalScheme: "http",
		},
		Database: config.Database{
			Driver:     config.DriverSQLite,
			SQLitePath: filepath.Join(t.TempDir(), "repos.db"),
			MaxConns:   1,
		},
	}
	ctx := context.Background()
	db, err := store.Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db, NewSQLiteQueries(lite.New(db.DB))
}

func TestUserRoundTrip(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, CreateUserParams{
		Username: "alice", PasswordHash: "argon2id$fake",
		DisplayName: "Alice", IsActive: true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if u.ID == 0 || u.Username != "alice" {
		t.Fatalf("unexpected user: %+v", u)
	}

	got, err := q.GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got.Username != "alice" || got.PasswordHash != "argon2id$fake" {
		t.Fatalf("unexpected user: %+v", got)
	}

	// Case-insensitive lookup.
	by, err := q.GetUserByUsername(ctx, "ALICE")
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if by.ID != u.ID {
		t.Fatalf("case-insensitive lookup returned %+v", by)
	}

	// narg-based listing with NULL filters must behave as "no filter".
	users, err := q.ListUsers(ctx, ListUsersParams{PageParams: PageParams{Limit: 10}})
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Fatalf("ListUsers returned %d rows, want 1", len(users))
	}
	n, err := q.CountUsers(ctx, CountUsersParams{})
	if err != nil {
		t.Fatalf("CountUsers: %v", err)
	}
	if n != 1 {
		t.Fatalf("CountUsers = %d, want 1", n)
	}

	// Versioned update with a stale version must match nothing.
	stale := UpdateUserParams{ID: u.ID, DisplayName: "Stale", IsActive: true, Version: u.Version + 99}
	if _, err := q.UpdateUser(ctx, stale); err == nil {
		t.Fatal("stale versioned update was accepted")
	}
	fresh := UpdateUserParams{ID: u.ID, DisplayName: "Alice L", IsActive: true, Version: u.Version}
	u2, err := q.UpdateUser(ctx, fresh)
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if u2.DisplayName != "Alice L" || u2.Version != u.Version+1 {
		t.Fatalf("unexpected updated user: %+v", u2)
	}

	// Soft delete.
	if err := q.SoftDeleteUser(ctx, u.ID); err != nil {
		t.Fatalf("SoftDeleteUser: %v", err)
	}
	if _, err := q.GetUserByID(ctx, u.ID); err == nil {
		t.Fatal("soft-deleted user is still returned")
	}

	// Password change clears the bootstrap flag.
	b, err := q.CreateUser(ctx, CreateUserParams{
		Username: "boot", PasswordHash: "h", IsActive: true,
		IsBootstrapDefault: true, MustChangePassword: true,
	})
	if err != nil {
		t.Fatalf("CreateUser(boot): %v", err)
	}
	b2, err := q.SetUserPassword(ctx, SetUserPasswordParams{ID: b.ID, PasswordHash: "new", MustChange: false})
	if err != nil {
		t.Fatalf("SetUserPassword: %v", err)
	}
	if b2.IsBootstrapDefault || b2.MustChangePassword {
		t.Fatalf("password change did not clear flags: %+v", b2)
	}
	n, err = q.CountUsersWithDefaultCredentials(ctx)
	if err != nil {
		t.Fatalf("CountUsersWithDefaultCredentials: %v", err)
	}
	if n != 0 {
		t.Fatalf("default-credential count = %d, want 0", n)
	}
}

func TestRolesAndPermissions(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	if err := q.CreatePermission(ctx, CreatePermissionParams{Name: domain.PermServersRead, Description: "read"}); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	perms, err := q.ListPermissions(ctx)
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != domain.PermServersRead {
		t.Fatalf("unexpected permissions: %v", perms)
	}

	r, err := q.CreateRole(ctx, CreateRoleParams{Name: "viewer", Description: "read-only"})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}
	if err := q.AddRolePermission(ctx, r.ID, domain.PermServersRead); err != nil {
		t.Fatalf("AddRolePermission: %v", err)
	}
	if err := q.AddRolePermission(ctx, r.ID, domain.PermServersRead); err != nil {
		t.Fatalf("idempotent AddRolePermission: %v", err)
	}
	rp, err := q.ListRolePermissions(ctx, r.ID)
	if err != nil {
		t.Fatalf("ListRolePermissions: %v", err)
	}
	if len(rp) != 1 {
		t.Fatalf("expected one permission, got %v", rp)
	}

	u, err := q.CreateUser(ctx, CreateUserParams{Username: "bob", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := q.AddUserRole(ctx, u.ID, r.ID); err != nil {
		t.Fatalf("AddUserRole: %v", err)
	}
	up, err := q.ListUserPermissions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserPermissions: %v", err)
	}
	if !domain.Has(up, domain.PermServersRead) {
		t.Fatalf("effective permissions missing: %v", up)
	}
	if err := q.RemoveUserRole(ctx, u.ID, r.ID); err != nil {
		t.Fatalf("RemoveUserRole: %v", err)
	}
	up, err = q.ListUserPermissions(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListUserPermissions: %v", err)
	}
	if len(up) != 0 {
		t.Fatalf("permissions survived role removal: %v", up)
	}
}

func TestSessions(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, CreateUserParams{Username: "sess", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	s, err := q.CreateSession(ctx, CreateSessionParams{
		ID: "sess-1", UserID: u.ID, TokenHash: []byte{1, 2, 3},
		IP: "203.0.113.1", UserAgent: "test", ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s.IP != "203.0.113.1" {
		t.Fatalf("unexpected session: %+v", s)
	}

	got, err := q.GetSessionByTokenHash(ctx, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if got.ID != "sess-1" {
		t.Fatalf("unexpected session: %+v", got)
	}

	if err := q.TouchSession(ctx, "sess-1"); err != nil {
		t.Fatalf("TouchSession: %v", err)
	}
	if err := q.RevokeSession(ctx, "sess-1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	// Revoked sessions must no longer resolve by token.
	if _, err := q.GetSessionByTokenHash(ctx, []byte{1, 2, 3}); err == nil {
		t.Fatal("revoked session still resolves by token")
	}
}

func TestLoginHistory(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, CreateUserParams{Username: "log", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	_, err = q.InsertLoginAttempt(ctx, InsertLoginAttemptParams{
		UserID: &u.ID, Username: "log", IP: "203.0.113.9",
		Success: false, FailureReason: domain.FailureBadPassword,
	})
	if err != nil {
		t.Fatalf("InsertLoginAttempt: %v", err)
	}
	ok := true
	hist, err := q.ListLoginHistory(ctx, LoginHistoryParams{
		PageParams: PageParams{Limit: 10}, Success: &ok,
	})
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if len(hist) != 0 {
		t.Fatalf("filter success=true returned failed attempts: %+v", hist)
	}
	f := false
	hist, err = q.ListLoginHistory(ctx, LoginHistoryParams{
		PageParams: PageParams{Limit: 10}, Success: &f, UserID: &u.ID,
	})
	if err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("unexpected history: %+v", hist)
	}
	if hist[0].FailureReason != domain.FailureBadPassword || hist[0].Success {
		t.Fatalf("unexpected history row: %+v", hist[0])
	}
}

func TestServersCredentialsHostKeys(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	s, err := q.CreateServer(ctx, CreateServerParams{
		Name: "vps1", TargetType: domain.TargetSSH, Host: "203.0.113.10",
		Port: 22, Username: "root", AuthMethod: domain.AuthKey,
		Tags: []byte(`["prod"]`), IsFavourite: true,
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if len(s.Tags) != 1 || s.Tags[0] != "prod" {
		t.Fatalf("tags did not round-trip: %+v", s.Tags)
	}

	if ok, err := q.ServerNameExists(ctx, "vps1", 0); err != nil || !ok {
		t.Fatalf("ServerNameExists = %v, %v", ok, err)
	}
	if ok, err := q.ServerNameExists(ctx, "vps1", s.ID); err != nil || ok {
		t.Fatalf("self-name check = %v, %v", ok, err)
	}

	_, err = q.UpdateServerStatus(ctx, UpdateServerStatusParams{ID: s.ID, Status: domain.StatusOnline})
	if err != nil {
		t.Fatalf("UpdateServerStatus: %v", err)
	}

	// Credentials are opaque ciphertext here; the adapter never decrypts.
	c, err := q.CreateCredential(ctx, CreateCredentialParams{
		ServerID: s.ID, Kind: domain.AuthKey, Ciphertext: []byte{9, 9, 9}, Version: 1,
	})
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	got, err := q.GetCredential(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if string(got.Ciphertext) != string(c.Ciphertext) {
		t.Fatal("ciphertext did not round-trip")
	}
	r, err := q.RotateCredential(ctx, CreateCredentialParams{
		ServerID: s.ID, Kind: domain.AuthKey, Ciphertext: []byte{8},
	})
	if err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}
	if r.Version != c.Version+1 {
		t.Fatalf("rotation did not bump version: %+v", r)
	}

	// Host keys.
	h, err := q.CreateHostKey(ctx, CreateHostKeyParams{
		ServerID: s.ID, Algorithm: "ssh-ed25519", Fingerprint: "SHA256:abc",
		PublicKey: []byte{1}, State: domain.HostKeyTrusted,
	})
	if err != nil {
		t.Fatalf("CreateHostKey: %v", err)
	}
	if h.State != domain.HostKeyTrusted {
		t.Fatalf("unexpected host key: %+v", h)
	}
	gh, err := q.GetHostKeyByFingerprint(ctx, s.ID, "SHA256:abc")
	if err != nil {
		t.Fatalf("GetHostKeyByFingerprint: %v", err)
	}
	if gh.ID != h.ID {
		t.Fatalf("fingerprint lookup mismatch: %+v", gh)
	}
}

func TestPerServerPermissions(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	if err := q.CreatePermission(ctx, CreatePermissionParams{Name: domain.PermMetricsRead}); err != nil {
		t.Fatalf("CreatePermission: %v", err)
	}
	u, err := q.CreateUser(ctx, CreateUserParams{Username: "scoped", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	s, err := q.CreateServer(ctx, CreateServerParams{
		Name: "scoped-1", Host: "203.0.113.11", Port: 22, Username: "u",
		AuthMethod: domain.AuthKey, Tags: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}

	if err := q.GrantServerPermission(ctx, GrantServerPermissionParams{
		UserID: u.ID, ServerID: s.ID, Permission: domain.PermMetricsRead,
	}); err != nil {
		t.Fatalf("GrantServerPermission: %v", err)
	}
	sp, err := q.ListServerPermissions(ctx, u.ID, s.ID)
	if err != nil {
		t.Fatalf("ListServerPermissions: %v", err)
	}
	if !domain.Has(sp, domain.PermMetricsRead) {
		t.Fatalf("grant missing: %v", sp)
	}
	ids, err := q.ListAccessibleServerIDs(ctx, u.ID)
	if err != nil {
		t.Fatalf("ListAccessibleServerIDs: %v", err)
	}
	if len(ids) != 1 || ids[0] != s.ID {
		t.Fatalf("accessible ids: %v", ids)
	}
	if err := q.ClearServerPermissions(ctx, u.ID, s.ID); err != nil {
		t.Fatalf("ClearServerPermissions: %v", err)
	}
	sp, err = q.ListServerPermissions(ctx, u.ID, s.ID)
	if err != nil {
		t.Fatalf("ListServerPermissions: %v", err)
	}
	if len(sp) != 0 {
		t.Fatalf("grants survived clearing: %v", sp)
	}
}

func TestAuditInsertAndQuery(t *testing.T) {
	db, q := openSQLite(t)
	ctx := context.Background()

	u, err := q.CreateUser(ctx, CreateUserParams{Username: "aud", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	e, err := q.InsertAudit(ctx, InsertAuditParams{
		ActorID: &u.ID, ActorName: "aud", Action: domain.ActionLoginSuccess,
		Result: domain.ResultSuccess, RequestID: "req-1", IP: "203.0.113.2",
		Metadata: []byte(`{"k":"v"}`),
	})
	if err != nil {
		t.Fatalf("InsertAudit: %v", err)
	}
	if e.ActorID == nil || *e.ActorID != u.ID || e.Metadata["k"] != "v" {
		t.Fatalf("unexpected event: %+v", e)
	}

	events, err := q.ListAudit(ctx, AuditQueryParams{PageParams: PageParams{Limit: 10}})
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("ListAudit returned %d events", len(events))
	}
	n, err := q.CountAudit(ctx, AuditQueryParams{})
	if err != nil {
		t.Fatalf("CountAudit: %v", err)
	}
	if n != 1 {
		t.Fatalf("CountAudit = %d", n)
	}

	// Transactional insert: the pair commits together.
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := q.InsertAuditTx(ctx, tx, InsertAuditParams{
		Action: domain.ActionLogout, Result: domain.ResultSuccess, RequestID: "req-2",
	}); err != nil {
		tx.Rollback()
		t.Fatalf("InsertAuditTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if n, err := q.CountAudit(ctx, AuditQueryParams{}); err != nil || n != 2 {
		t.Fatalf("CountAudit after tx = %d, %v", n, err)
	}

	// A rolled-back insert must leave no trace.
	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := q.InsertAuditTx(ctx, tx2, InsertAuditParams{
		Action: domain.ActionLogout, Result: domain.ResultSuccess, RequestID: "req-3",
	}); err != nil {
		tx2.Rollback()
		t.Fatalf("InsertAuditTx: %v", err)
	}
	tx2.Rollback()
	if n, err := q.CountAudit(ctx, AuditQueryParams{}); err != nil || n != 2 {
		t.Fatalf("rolled-back insert leaked: count = %d, %v", n, err)
	}
}

func TestJobLifecycle(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	j, err := q.EnqueueJob(ctx, EnqueueJobParams{Kind: "metrics", MaxAttempts: 3, RunAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	claimed, err := q.ClaimJob(ctx, "worker-1")
	if err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	if claimed.ID != j.ID || claimed.Status != domain.JobRunning || claimed.LockedBy == nil {
		t.Fatalf("unexpected claim: %+v", claimed)
	}
	// No further claim while one job exists.
	if _, err := q.ClaimJob(ctx, "worker-2"); err == nil {
		t.Fatal("second claim on an empty queue was accepted")
	}
	if err := q.HeartbeatJob(ctx, j.ID); err != nil {
		t.Fatalf("HeartbeatJob: %v", err)
	}
	if err := q.UpdateJobProgress(ctx, j.ID, 0.5); err != nil {
		t.Fatalf("UpdateJobProgress: %v", err)
	}
	if err := q.CompleteJob(ctx, j.ID); err != nil {
		t.Fatalf("CompleteJob: %v", err)
	}
	done, err := q.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if done.Status != domain.JobSucceeded || done.Progress != 1 {
		t.Fatalf("unexpected completion: %+v", done)
	}
}

func TestJobFailRetryDead(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	j, err := q.EnqueueJob(ctx, EnqueueJobParams{Kind: "backup", MaxAttempts: 3, RunAt: time.Now().UTC()})
	if err != nil {
		t.Fatalf("EnqueueJob: %v", err)
	}
	if _, err := q.ClaimJob(ctx, "w"); err != nil {
		t.Fatalf("ClaimJob: %v", err)
	}
	when := time.Now().Add(time.Minute).UTC()
	if err := q.FailJob(ctx, j.ID, when, "transient"); err != nil {
		t.Fatalf("FailJob: %v", err)
	}
	got, err := q.GetJob(ctx, j.ID)
	if err != nil {
		t.Fatalf("GetJob: %v", err)
	}
	if got.Status != domain.JobRetrying {
		t.Fatalf("expected retrying, got %+v", got.Status)
	}
	n, err := q.PromoteRetryingJobs(ctx)
	_ = n
	_ = err
	if err := q.DeadJob(ctx, j.ID, "exhausted"); err != nil {
		t.Fatalf("DeadJob: %v", err)
	}
	if got, err := q.GetJob(ctx, j.ID); err != nil || got.Status != domain.JobDead {
		t.Fatalf("expected dead: %+v %v", got, err)
	}
	if err := q.CancelJob(ctx, j.ID); err != nil {
		t.Fatalf("CancelJob terminal: %v", err)
	}
}

func TestMetricUpsertAndLatest(t *testing.T) {
	_, q := openSQLite(t)
	ctx := context.Background()

	s, err := q.CreateServer(ctx, CreateServerParams{
		Name: "m1", Host: "h", Port: 22, Username: "u",
		AuthMethod: domain.AuthKey, Tags: []byte("[]"),
	})
	if err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	ts := time.Now().UTC().Truncate(time.Second)
	cpu := 12.5
	mem := int64(4096)
	for i := 0; i < 3; i++ {
		if err := q.UpsertMetricSample(ctx, domain.MetricSample{
			ServerID: s.ID, Timestamp: ts, CPUPct: &cpu, MemUsed: &mem,
		}); err != nil {
			t.Fatalf("UpsertMetricSample: %v", err)
		}
	}
	latest, err := q.GetLatestMetricSample(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetLatestMetricSample: %v", err)
	}
	if latest.CPUPct == nil || *latest.CPUPct != 12.5 {
		t.Fatalf("unexpected sample: %+v", latest)
	}
	// An uncollected metric stays nil rather than zero.
	if err := q.UpsertMetricSample(ctx, domain.MetricSample{
		ServerID: s.ID, Timestamp: ts.Add(time.Second),
	}); err != nil {
		t.Fatalf("UpsertMetricSample empty: %v", err)
	}
	empty, err := q.GetLatestMetricSample(ctx, s.ID)
	if err != nil {
		t.Fatalf("GetLatestMetricSample: %v", err)
	}
	if empty.CPUPct != nil {
		t.Fatalf("absent metric came back as a value: %+v", empty.CPUPct)
	}

	// Filesystems.
	used := int64(500)
	tot := int64(1000)
	if err := q.UpsertMetricFilesystem(ctx, domain.Filesystem{
		ServerID: s.ID, Timestamp: ts, MountPoint: "/", TotalBytes: &tot, UsedBytes: &used,
	}); err != nil {
		t.Fatalf("UpsertMetricFilesystem: %v", err)
	}
	fs, err := q.ListLatestFilesystems(ctx, s.ID)
	if err != nil {
		t.Fatalf("ListLatestFilesystems: %v", err)
	}
	if len(fs) != 1 || fs[0].MountPoint != "/" {
		t.Fatalf("unexpected filesystems: %+v", fs)
	}
}

func TestPostgresParity(t *testing.T) {
	dsn := postgresDSN(t)
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL parity test")
	}
	dsn = withTestSchema(t, dsn, pgReposTestSchema)
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
	t.Cleanup(func() { db.Close() })
	if _, err := db.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+pgReposTestSchema+" CASCADE; CREATE SCHEMA "+pgReposTestSchema+";"); err != nil {
		t.Fatalf("reset: %v", err)
	}
	if err := store.Migrate(ctx, db, nil); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	var schema string
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	if schema != pgReposTestSchema {
		t.Fatalf("current_schema = %q, want %q: search_path isolation is not in effect", schema, pgReposTestSchema)
	}
	pool := db.PGXPool()
	if pool == nil {
		t.Fatal("postgres test database has no pgx pool")
	}
	q := NewPostgresQueries(pg.New(pool))

	// A representative subset: the adapters are generated from the same logical
	// queries, so one domain exercised end to end on both dialects proves the
	// mapping holds. The full matrix already runs for SQLite above.
	u, err := q.CreateUser(ctx, CreateUserParams{Username: "pguser", PasswordHash: "h", IsActive: true})
	if err != nil {
		t.Fatalf("pg CreateUser: %v", err)
	}
	got, err := q.GetUserByUsername(ctx, "PGUSER")
	if err != nil {
		t.Fatalf("pg case-insensitive lookup: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("pg lookup mismatch")
	}
	e, err := q.InsertAudit(ctx, InsertAuditParams{
		ActorID: &u.ID, ActorName: "pguser", Action: domain.ActionLoginSuccess,
		Result: domain.ResultSuccess, RequestID: "pg-1",
	})
	if err != nil {
		t.Fatalf("pg InsertAudit: %v", err)
	}
	if e.ActorID == nil || *e.ActorID != u.ID {
		t.Fatalf("pg audit mismatch: %+v", e)
	}
}
