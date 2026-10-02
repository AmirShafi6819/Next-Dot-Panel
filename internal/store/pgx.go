package store

import (
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgxHandle keeps the native pgx pool for postgres. The pgx-generated sqlc
// code needs a pgx-native connection (pgxpool.Pool or pgx.Tx); *sql.Tx does
// not satisfy its DBTX interface, so the pool is carried here and handed to
// the postgres adapter instead of leaking pgx plumbing into services.
type pgxHandle struct {
	pool *pgxpool.Pool
}

// PGXPool returns the underlying pgx pool for postgres, or nil for sqlite.
// Tests and the postgres adapter use this to build pgx-native query sets.
func (d *DB) PGXPool() *pgxpool.Pool {
	if d == nil || d.pgxh == nil {
		return nil
	}
	return d.pgxh.pool
}
