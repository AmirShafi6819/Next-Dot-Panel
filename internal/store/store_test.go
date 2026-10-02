package store

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
)

// rebind converts '?' placeholders to the numbered form PostgreSQL requires.
//
// Production code never needs this: sqlc generates a dialect-correct query for
// each driver. The tests share one handwritten set of statements, so they
// rebind. Quoted string literals are skipped so a '?' inside a literal is not
// mistaken for a placeholder.
func rebind(driver, query string) string {
	if driver != config.DriverPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 0
	inString := false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if c == '\'' {
			inString = !inString
		}
		if c == '?' && !inString {
			n++
			b.WriteByte('$')
			b.WriteString(strconv.Itoa(n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// exec runs a statement with dialect-correct placeholders, failing the test on
// error.
func exec(t *testing.T, db *DB, query string, args ...any) sql.Result {
	t.Helper()
	res, err := db.ExecContext(context.Background(), rebind(db.Driver, query), args...)
	if err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
	return res
}

// execErr runs a statement that is expected to fail, returning the error so
// the caller can assert on it.
func execErr(db *DB, query string, args ...any) error {
	_, err := db.ExecContext(context.Background(), rebind(db.Driver, query), args...)
	return err
}

// row starts a single-row query with dialect-correct placeholders.
func row(t *testing.T, db *DB, query string, args ...any) *sql.Row {
	t.Helper()
	return db.QueryRowContext(context.Background(), rebind(db.Driver, query), args...)
}

// sqliteConfig returns a config backed by a temporary SQLite file.
func sqliteConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		Env: config.EnvDevelopment,
		App: config.App{
			Env:            config.EnvDevelopment,
			DataDir:        dir,
			LogLevel:       "ERROR",
			LogFormat:      "text",
			ExternalScheme: "http",
		},
		Database: config.Database{
			Driver:     config.DriverSQLite,
			SQLitePath: filepath.Join(dir, "test.db"),
			MaxConns:   1,
		},
	}
}

// postgresConfig returns a config for the database named by TEST_DATABASE_URL,
// or nil when that variable is unset. Integration tests skip cleanly in that
// case so the suite runs anywhere.
func postgresConfig(t *testing.T) *config.Config {
	t.Helper()
	dsn := lookupTestDSN(t)
	if dsn == "" {
		return nil
	}
	return &config.Config{
		Env: config.EnvDevelopment,
		App: config.App{
			Env:            config.EnvDevelopment,
			DataDir:        t.TempDir(),
			LogLevel:       "ERROR",
			LogFormat:      "text",
			ExternalScheme: "http",
		},
		Database: config.Database{
			Driver:   config.DriverPostgres,
			DSN:      withTestSchema(t, dsn, pgTestSchema),
			MaxConns: 5,
		},
	}
}

// forEachDialect runs fn against every configured dialect.
func forEachDialect(t *testing.T, fn func(t *testing.T, db *DB)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) {
		cfg := sqliteConfig(t)
		ctx := context.Background()
		db, err := Open(ctx, cfg, nil)
		if err != nil {
			t.Fatalf("open sqlite: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if err := Migrate(ctx, db, nil); err != nil {
			t.Fatalf("migrate sqlite: %v", err)
		}
		fn(t, db)
	})

	t.Run("postgres", func(t *testing.T) {
		cfg := postgresConfig(t)
		if cfg == nil {
			t.Skip("TEST_DATABASE_URL is not set; skipping PostgreSQL integration test")
		}
		ctx := context.Background()
		db, err := Open(ctx, cfg, nil)
		if err != nil {
			t.Fatalf("open postgres: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		if _, err := db.ExecContext(ctx, "DROP SCHEMA IF EXISTS "+pgTestSchema+" CASCADE; CREATE SCHEMA "+pgTestSchema+";"); err != nil {
			t.Fatalf("reset postgres schema: %v", err)
		}
		if err := Migrate(ctx, db, nil); err != nil {
			t.Fatalf("migrate postgres: %v", err)
		}
		assertCurrentSchema(t, db, pgTestSchema)
		fn(t, db)
	})
}

func TestRebind(t *testing.T) {
	// PostgreSQL needs numbered placeholders; SQLite must be left untouched.
	got := rebind(config.DriverPostgres, "INSERT INTO t (a, b) VALUES (?, ?) AND c = ?")
	want := "INSERT INTO t (a, b) VALUES ($1, $2) AND c = $3"
	if got != want {
		t.Fatalf("postgres rebind = %q, want %q", got, want)
	}

	// A '?' inside a string literal is not a placeholder.
	got = rebind(config.DriverPostgres, "SELECT * FROM t WHERE a = 'what?' AND b = ?")
	want = "SELECT * FROM t WHERE a = 'what?' AND b = $1"
	if got != want {
		t.Fatalf("rebind with quoted '?' = %q, want %q", got, want)
	}

	plain := "SELECT * FROM t WHERE a = ?"
	if rebind(config.DriverSQLite, plain) != plain {
		t.Fatal("sqlite queries must not be rebound")
	}
}

func TestMigrateCreatesSchema(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		ctx := context.Background()

		version, err := SchemaVersion(ctx, db)
		if err != nil {
			t.Fatalf("read schema version: %v", err)
		}
		if version < 1 {
			t.Fatalf("schema version = %d, want at least 1", version)
		}

		checks := []string{
			"SELECT count(*) FROM users",
			"SELECT count(*) FROM roles",
			"SELECT count(*) FROM permissions",
			"SELECT count(*) FROM role_permissions",
			"SELECT count(*) FROM user_roles",
			"SELECT count(*) FROM sessions",
			"SELECT count(*) FROM servers",
			"SELECT count(*) FROM server_credentials",
			"SELECT count(*) FROM server_host_keys",
			"SELECT count(*) FROM tags",
			"SELECT count(*) FROM server_tags",
			"SELECT count(*) FROM server_permissions",
			"SELECT count(*) FROM audit_logs",
			"SELECT count(*) FROM login_history",
			"SELECT count(*) FROM application_logs",
			"SELECT count(*) FROM metric_samples",
			"SELECT count(*) FROM metric_aggregates",
			"SELECT count(*) FROM metric_filesystems",
			"SELECT count(*) FROM terminal_sessions",
			"SELECT count(*) FROM jobs",
			"SELECT count(*) FROM api_tokens",
			"SELECT count(*) FROM settings",
			"SELECT count(*) FROM notification_channels",
			"SELECT count(*) FROM notifications",
			"SELECT count(*) FROM backups",
		}
		for _, q := range checks {
			var n int
			if err := row(t, db, q).Scan(&n); err != nil {
				t.Errorf("query failed: %s: %v", q, err)
			}
		}
	})
}

func TestMigrateIsIdempotent(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		if err := Migrate(context.Background(), db, nil); err != nil {
			t.Fatalf("second migrate: %v", err)
		}
	})
}

func TestForeignKeysAreEnforced(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		// A session referencing a nonexistent user must be rejected. On SQLite
		// this holds only because the connection enables foreign_keys, so this
		// test is what proves that pragma took effect.
		err := execErr(db,
			`INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
			"sess-1", int64(999999), []byte{1, 2, 3}, time.Now().Add(time.Hour).UTC())
		if err == nil {
			t.Fatal("inserting a session with a dangling user_id was allowed; foreign keys are not enforced")
		}
	})
}

func TestUniqueConstraintsAreEnforced(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		exec(t, db, `INSERT INTO users (username, password_hash) VALUES (?, ?)`, "dup", "hash")
		if err := execErr(db,
			`INSERT INTO users (username, password_hash) VALUES (?, ?)`, "dup", "hash"); err == nil {
			t.Fatal("duplicate username was allowed")
		}
		// The unique index is on lower(username), so different casing must
		// also be rejected.
		if err := execErr(db,
			`INSERT INTO users (username, password_hash) VALUES (?, ?)`, "DUP", "hash"); err == nil {
			t.Fatal("duplicate username differing only in case was allowed")
		}
	})
}

func TestSoftDeletedUsernameCanBeReused(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		exec(t, db, `INSERT INTO users (username, password_hash) VALUES (?, ?)`, "recycled", "hash")
		exec(t, db, `UPDATE users SET deleted_at = ? WHERE username = ?`, time.Now().UTC(), "recycled")

		// The partial unique index excludes soft-deleted rows, so the name is
		// free again while the original row (and its audit history) survives.
		exec(t, db, `INSERT INTO users (username, password_hash) VALUES (?, ?)`, "recycled", "hash")
	})
}

func TestCascadeDeleteRemovesDependentRows(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		var userID int64
		if err := row(t, db,
			`INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id`,
			"cascade", "hash").Scan(&userID); err != nil {
			t.Fatalf("insert user: %v", err)
		}

		exec(t, db,
			`INSERT INTO sessions (id, user_id, token_hash, expires_at) VALUES (?, ?, ?, ?)`,
			"sess-c", userID, []byte{9}, time.Now().Add(time.Hour).UTC())

		exec(t, db, `DELETE FROM users WHERE id = ?`, userID)

		var n int
		if err := row(t, db, `SELECT count(*) FROM sessions WHERE user_id = ?`, userID).Scan(&n); err != nil {
			t.Fatalf("count sessions: %v", err)
		}
		if n != 0 {
			t.Fatalf("%d sessions survived the user delete; cascade is not firing", n)
		}
	})
}

func TestAuditLogDefaults(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		var id int64
		if err := row(t, db,
			`INSERT INTO audit_logs (action, result) VALUES (?, ?) RETURNING id`,
			"TEST_ACTION", "SUCCESS").Scan(&id); err != nil {
			t.Fatalf("insert audit: %v", err)
		}

		var action, result, actorName string
		var ts time.Time
		if err := row(t, db,
			`SELECT action, result, actor_name, ts FROM audit_logs WHERE id = ?`, id).
			Scan(&action, &result, &actorName, &ts); err != nil {
			t.Fatalf("read audit: %v", err)
		}
		if action != "TEST_ACTION" || result != "SUCCESS" {
			t.Fatalf("audit row round-tripped as %q/%q", action, result)
		}
		if ts.IsZero() {
			t.Fatal("audit timestamp was not populated by the column default")
		}
		if actorName != "" {
			t.Fatalf("actor_name default = %q, want empty", actorName)
		}
	})
}

func TestTimestampRoundTrip(t *testing.T) {
	// SQLite stores timestamps as TEXT via a strftime default. If that format
	// were not directly comparable with what Go writes, every range query
	// would silently match nothing -- a bug that would look like "no data"
	// rather than an error.
	forEachDialect(t, func(t *testing.T, db *DB) {
		var userID int64
		if err := row(t, db,
			`INSERT INTO users (username, password_hash) VALUES (?, ?) RETURNING id`,
			"timestamps", "hash").Scan(&userID); err != nil {
			t.Fatalf("insert: %v", err)
		}

		var created time.Time
		if err := row(t, db,
			`SELECT created_at FROM users WHERE id = ?`, userID).Scan(&created); err != nil {
			t.Fatalf("scan created_at: %v (the column default is not in a format Go can parse)", err)
		}
		if created.IsZero() {
			t.Fatal("created_at scanned as the zero time")
		}
		if delta := time.Since(created); delta > time.Hour || delta < -time.Hour {
			t.Fatalf("created_at is %s away from now; timezone handling is wrong", delta)
		}

		// A range query with Go-written bounds must match a row written with
		// the column default.
		var n int
		if err := row(t, db,
			`SELECT count(*) FROM users WHERE created_at >= ? AND created_at <= ?`,
			time.Now().Add(-time.Hour).UTC(), time.Now().Add(time.Hour).UTC()).Scan(&n); err != nil {
			t.Fatalf("range query: %v", err)
		}
		if n != 1 {
			t.Fatalf("range query matched %d rows, want 1; stored and queried timestamp formats differ", n)
		}
	})
}

func TestNullableMetricIsNotZero(t *testing.T) {
	// A metric that could not be collected must be NULL, never 0, so the UI
	// can tell "absent" apart from "actually zero".
	forEachDialect(t, func(t *testing.T, db *DB) {
		var serverID int64
		if err := row(t, db,
			`INSERT INTO servers (name, host, port, username, auth_method, tags)
			 VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
			"metrics", "203.0.113.10", 22, "root", "key", []byte("[]")).Scan(&serverID); err != nil {
			t.Fatalf("insert server: %v", err)
		}

		ts := time.Now().UTC().Truncate(time.Second)
		exec(t, db,
			`INSERT INTO metric_samples (server_id, ts, cpu_pct, mem_used) VALUES (?, ?, ?, ?)`,
			serverID, ts, nil, int64(1024))

		var cpu *float64
		var mem *int64
		if err := row(t, db,
			`SELECT cpu_pct, mem_used FROM metric_samples WHERE server_id = ? AND ts = ?`,
			serverID, ts).Scan(&cpu, &mem); err != nil {
			t.Fatalf("scan metric: %v", err)
		}
		if cpu != nil {
			t.Fatalf("uncollected cpu_pct came back as %v, want NULL", *cpu)
		}
		if mem == nil || *mem != 1024 {
			t.Fatalf("collected mem_used round-tripped incorrectly: %v", mem)
		}
	})
}

func TestMetricUpsertIsIdempotent(t *testing.T) {
	// Replaying the same sample must overwrite, not duplicate: a retried
	// collection job would otherwise compound rows.
	forEachDialect(t, func(t *testing.T, db *DB) {
		var serverID int64
		if err := row(t, db,
			`INSERT INTO servers (name, host, port, username, auth_method, tags)
			 VALUES (?, ?, ?, ?, ?, ?) RETURNING id`,
			"upsert", "203.0.113.20", 22, "root", "key", []byte("[]")).Scan(&serverID); err != nil {
			t.Fatalf("insert server: %v", err)
		}

		ts := time.Now().UTC().Truncate(time.Second)
		for i := 0; i < 3; i++ {
			exec(t, db,
				`INSERT INTO metric_samples (server_id, ts, cpu_pct) VALUES (?, ?, ?)
				 ON CONFLICT (server_id, ts) DO UPDATE SET cpu_pct = EXCLUDED.cpu_pct`,
				serverID, ts, float64(i))
		}

		var n int
		var cpu *float64
		if err := row(t, db,
			`SELECT count(*), max(cpu_pct) FROM metric_samples WHERE server_id = ?`, serverID).
			Scan(&n, &cpu); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n != 1 {
			t.Fatalf("upsert produced %d rows, want 1", n)
		}
		if cpu == nil || *cpu != 2 {
			t.Fatalf("upsert did not apply the last value: %v", cpu)
		}
	})
}

func TestSettingsUniqueUpsert(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		for i := 0; i < 3; i++ {
			exec(t, db,
				`INSERT INTO settings (key, value) VALUES (?, ?)
				 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`,
				"theme", []byte(`"dark"`))
		}
		var n int
		if err := row(t, db, `SELECT count(*) FROM settings WHERE key = ?`, "theme").Scan(&n); err != nil {
			t.Fatalf("count settings: %v", err)
		}
		if n != 1 {
			t.Fatalf("upsert produced %d rows, want 1", n)
		}
	})
}

func TestOptimisticLockingRejectsStaleVersion(t *testing.T) {
	forEachDialect(t, func(t *testing.T, db *DB) {
		var serverID, version int64
		if err := row(t, db,
			`INSERT INTO servers (name, host, port, username, auth_method, tags)
			 VALUES (?, ?, ?, ?, ?, ?) RETURNING id, version`,
			"optlock", "203.0.113.30", 22, "root", "key", []byte("[]")).Scan(&serverID, &version); err != nil {
			t.Fatalf("insert server: %v", err)
		}

		// First update with the current version succeeds.
		var newVersion int64
		if err := row(t, db,
			`UPDATE servers SET name = ?, version = version + 1
			 WHERE id = ? AND version = ? RETURNING version`,
			"optlock-renamed", serverID, version).Scan(&newVersion); err != nil {
			t.Fatalf("first versioned update: %v", err)
		}

		// Replaying the now-stale version must match nothing, so a second
		// administrator cannot silently overwrite the first.
		var ignored int64
		err := row(t, db,
			`UPDATE servers SET name = ?, version = version + 1
			 WHERE id = ? AND version = ? RETURNING version`,
			"stale-overwrite", serverID, version).Scan(&ignored)
		if err == nil {
			t.Fatal("a stale version was accepted; concurrent edits would silently overwrite")
		}
		if err != sql.ErrNoRows {
			t.Fatalf("expected sql.ErrNoRows for a stale version, got %v", err)
		}
	})
}

func TestPingAndClose(t *testing.T) {
	cfg := sqliteConfig(t)
	ctx := context.Background()
	db, err := Open(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := db.Ping(ctx); err == nil {
		t.Fatal("ping succeeded after Close")
	}
}
