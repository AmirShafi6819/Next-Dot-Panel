package store

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
)

// pgTestSchema is the schema this package's PostgreSQL integration tests run
// in. It is deliberately not `public`: go test runs packages concurrently, so
// internal/store and internal/store/repos, when pointed at the same
// TEST_DATABASE_URL, must not drop each other's tables.
const pgTestSchema = "nextpanel_store_test"

// withTestSchema returns dsn with search_path pinned to schema, so every table
// created through the returned connection lands there regardless of the login
// role's default search_path.
//
// search_path is passed as a plain startup parameter rather than through
// libpq's `options`: the backend applies unknown startup parameters as GUC
// assignments, and a raw parameter avoids depending on how the URL encoder
// spells the space inside `-c search_path=...` (it turned `+` into a literal
// `+`, producing "unrecognized configuration parameter").
func withTestSchema(t *testing.T, dsn, schema string) string {
	t.Helper()

	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse TEST_DATABASE_URL: %v", err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		return u.String()
	}

	// keyword/value form: the schema name is a plain identifier, no quoting.
	return dsn + " search_path=" + schema
}

// assertCurrentSchema fails the test when connections are not actually
// isolated to want. A search_path that PostgreSQL ignored (for example because
// the startup parameter was dropped somewhere) would otherwise mean these
// tests drop and migrate the wrong schema — silently, until two packages race.
func assertCurrentSchema(t *testing.T, db *DB, want string) {
	t.Helper()

	var got string
	if err := db.QueryRowContext(context.Background(), "SELECT current_schema()").Scan(&got); err != nil {
		t.Fatalf("current_schema: %v", err)
	}
	if got != want {
		t.Fatalf("current_schema = %q, want %q: search_path isolation is not in effect", got, want)
	}
}

// lookupTestDSN returns the PostgreSQL DSN for integration tests.
//
// Only TEST_DATABASE_URL is honoured, deliberately: pointing a test at a
// developer's or production database by accident would be destructive, since
// the PostgreSQL suite drops and recreates its schema (pgTestSchema). A
// separate, obviously-test-only variable makes that mistake unlikely.
func lookupTestDSN(t *testing.T) string {
	t.Helper()

	if os.Getenv("NEXT_PANEL_ENV") == "production" {
		t.Fatal("refusing to run destructive store tests with NEXT_PANEL_ENV=production")
	}
	if os.Getenv("NEXT_PANEL_DB_DRIVER") == "postgres" && os.Getenv("NEXT_PANEL_DB_DSN") != "" {
		t.Fatal("refusing to run: NEXT_PANEL_DB_DSN is set and these tests drop the schema")
	}
	return os.Getenv("TEST_DATABASE_URL")
}
