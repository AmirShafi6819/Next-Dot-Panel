package repos

import (
	"time"

	"github.com/ashaibery/Next-Dot-Panel/internal/domain"
)

// optID dereferences a nullable user ID into the *int64 that pgx-generated
// code takes for nullable foreign keys. Both dialects generate pointer types
// for nullable columns (emit_pointers_for_null_types with sql_package pgx/v5).
func optID(id *domain.UserID) *int64 {
	if id == nil {
		return nil
	}
	v := int64(*id)
	return &v
}

// optServerID dereferences a nullable server ID the same way.
func optServerID(id *domain.ServerID) *int64 {
	if id == nil {
		return nil
	}
	v := int64(*id)
	return &v
}

// optIDValue is an alias for optID, kept for backward compatibility.
func optIDValue(id *domain.UserID) *int64 {
	return optID(id)
}

// nullString passes an optional string filter straight through: with
// sql_package pgx/v5, sqlc emits *string for sqlc.narg text columns.
func nullString(p *string) *string {
	return p
}

// nullTime passes an optional timestamp filter straight through for the same
// reason.
func nullTime(p *time.Time) *time.Time {
	return p
}

// i32 narrows an int64 onto the int32 the PostgreSQL generator emits for
// counters and LIMIT/OFFSET. Every value reaching this layer is already
// clamped by the domain (page sizes cap at 200; ids come from the database),
// so the clamp is belt-and-braces rather than load-bearing.
func i32(v int64) int32 {
	if v > 1<<31-1 {
		return 1<<31 - 1
	}
	if v < -1<<31 {
		return -1 << 31
	}
	return int32(v)
}

// nullString passes an optional string filter straight through: with
// sql_package pgx/v5, sqlc emits *string for sqlc.narg text columns, matching
// the neutral interface exactly.

func ptrFromNullString(p *string) *string {
	return p
}

func ptrFromNullTime(p *time.Time) *time.Time {
	return p
}

// jsonOr substitutes a valid JSON literal when the caller supplied none, so a
// NOT NULL jsonb/json column never receives an empty byte slice.
func jsonOr(v []byte, fallback string) []byte {
	if len(v) == 0 {
		return []byte(fallback)
	}
	return v
}

// parseSQLiteTimePtr parses SQLite's TEXT timestamp (RFC3339 format with 'T'
// separator and 'Z' suffix) into a *time.Time. Returns nil for empty/zero strings.
func parseSQLiteTimePtr(s string) *time.Time {
	if s == "" || s == "0001-01-01T00:00:00Z" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// parseSQLiteTimePtrStr parses a nullable SQLite TEXT timestamp. sqlc generates
// nullable timestamps as *string because the ncruces driver returns TEXT as Go
// string and database/sql cannot scan either a string into **time.Time or NULL
// into a plain string (docs/research.md F5).
func parseSQLiteTimePtrStr(p *string) *time.Time {
	if p == nil {
		return nil
	}
	return parseSQLiteTimePtr(*p)
}

// sqliteTimeFormat matches SQLite's strftime('%Y-%m-%dT%H:%M:%fZ') exactly:
// fixed-width milliseconds keep the stored TEXT lexicographically ordered, so
// range comparisons against strftime-generated values stay correct. Go's
// RFC3339Nano would drop the fraction and sort "…:00Z" after "…:00.500Z".
const sqliteTimeFormat = "2006-01-02T15:04:05.000Z"

// formatSQLiteTimePtr formats a nullable Go timestamp as a SQLite TEXT
// parameter. nil stays nil so the column keeps its NULL.
func formatSQLiteTimePtr(t *time.Time) *string {
	if t == nil || t.IsZero() {
		return nil
	}
	s := t.UTC().Format(sqliteTimeFormat)
	return &s
}
