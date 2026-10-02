package repos

import (
	"net/url"
	"os"
	"strings"
	"testing"
)

// pgReposTestSchema is the schema the parity test runs in. It is deliberately
// not `public`: go test runs packages concurrently, so internal/store and
// internal/store/repos, when pointed at the same TEST_DATABASE_URL, must not
// drop each other's tables.
const pgReposTestSchema = "nextpanel_repos_test"

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

// postgresDSN returns the PostgreSQL DSN for the parity test, or "" when
// unset. The parity test skips cleanly without it so the suite runs anywhere.
func postgresDSN(t *testing.T) string {
	t.Helper()
	if os.Getenv("NEXT_PANEL_ENV") == "production" {
		t.Fatal("refusing to run destructive store tests with NEXT_PANEL_ENV=production")
	}
	return os.Getenv("TEST_DATABASE_URL")
}
