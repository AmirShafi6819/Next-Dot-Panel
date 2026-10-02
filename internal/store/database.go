// Package store owns the database connection, schema migrations, and the
// generated SQL layer for both supported dialects.
//
// Application services never import the generated packages directly. They use
// the repository interfaces in internal/store/repos, which sit on top of the
// adapter layer. The reason is measured, not stylistic: sqlc emits different
// Go types per dialect (int32 vs int64 for LIMIT, *int64 vs interface{} for
// optional parameters), so generated types cannot be the application's types.
// See docs/research.md 1.4.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/ncruces/go-sqlite3/driver"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
)

// DB wraps a database handle plus the dialect it speaks.
//
// PostgreSQL also keeps the native pgx pool: the pgx-generated sqlc code
// needs a pgx-native connection (pgxpool.Pool or pgx.Tx), and *sql.Tx does
// not satisfy its DBTX interface. Carrying the pool here keeps all of that
// plumbing inside the store package instead of leaking it into services.
type DB struct {
	Driver string // config.DriverPostgres or config.DriverSQLite
	*sql.DB
	pgxh *pgxHandle
}

// IsSQLite reports whether the connection speaks SQLite.
func (d *DB) IsSQLite() bool { return d.Driver == config.DriverSQLite }

// IsPostgres reports whether the connection speaks PostgreSQL.
func (d *DB) IsPostgres() bool { return d.Driver == config.DriverPostgres }

// Open establishes a database connection for the configured driver and waits
// until it is actually reachable.
func Open(ctx context.Context, cfg *config.Config, log logger) (*DB, error) {
	switch cfg.Database.Driver {
	case config.DriverPostgres:
		return openPostgres(ctx, cfg, log)
	case config.DriverSQLite:
		return openSQLite(ctx, cfg, log)
	default:
		return nil, fmt.Errorf("store: unsupported driver %q", cfg.Database.Driver)
	}
}

type logger interface {
	Info(ctx context.Context, msg string, args ...any)
	Warn(ctx context.Context, msg string, args ...any)
	Error(ctx context.Context, msg string, args ...any)
}

func openPostgres(ctx context.Context, cfg *config.Config, log logger) (*DB, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: invalid postgres DSN: %w", err)
	}
	poolCfg.MaxConns = int32(cfg.Database.MaxConns)
	poolCfg.MinConns = 1
	poolCfg.MaxConnLifetime = time.Hour
	poolCfg.MaxConnIdleTime = 30 * time.Minute
	poolCfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect postgres: %w", err)
	}

	// Fail fast at startup rather than on the first request.
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: postgres is not reachable: %w", err)
	}

	db := stdlib.OpenDBFromPool(pool)
	db.SetMaxOpenConns(cfg.Database.MaxConns)

	if log != nil {
		log.Info(ctx, "connected to postgres", "max_conns", cfg.Database.MaxConns)
	}
	return &DB{Driver: config.DriverPostgres, DB: db, pgxh: &pgxHandle{pool: pool}}, nil
}

func openSQLite(ctx context.Context, cfg *config.Config, log logger) (*DB, error) {
	// The pragmas matter and are not defaults:
	//   journal_mode=WAL   concurrent readers alongside one writer
	//   busy_timeout       wait rather than failing immediately on contention
	//   foreign_keys       SQLite disables FK enforcement per connection by
	//                      default, so ON DELETE CASCADE would silently not fire
	//   synchronous=NORMAL durable under WAL while avoiding a fsync per commit
	dsn := "file:" + cfg.Database.SQLitePath +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(1)" +
		"&_pragma=synchronous(NORMAL)"

	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}

	// SQLite permits a single writer. A larger pool produces SQLITE_BUSY under
	// concurrent writes rather than more throughput, so the pool is pinned to
	// one connection and all database access serialises. This is a documented
	// limitation (Design Spec 7.4), not an oversight.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: sqlite is not reachable at %s: %w", cfg.Database.SQLitePath, err)
	}

	if err := verifySQLitePragmas(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	if log != nil {
		log.Info(ctx, "connected to sqlite", "path", cfg.Database.SQLitePath)
	}
	return &DB{Driver: config.DriverSQLite, DB: db}, nil
}

// verifySQLitePragmas confirms the pragmas actually took effect. A silent
// failure here would mean foreign keys are unenforced or writes are not
// durable, which would be discovered only much later.
func verifySQLitePragmas(ctx context.Context, db *sql.DB) error {
	var journal string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
		return fmt.Errorf("store: reading journal_mode: %w", err)
	}
	if journal != "wal" {
		return fmt.Errorf("store: sqlite journal_mode is %q, expected wal", journal)
	}

	var foreignKeys int
	if err := db.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		return fmt.Errorf("store: reading foreign_keys: %w", err)
	}
	if foreignKeys != 1 {
		return errors.New("store: sqlite foreign key enforcement is off; ON DELETE CASCADE would not fire")
	}

	var busyTimeout int
	if err := db.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err != nil {
		return fmt.Errorf("store: reading busy_timeout: %w", err)
	}
	if busyTimeout != 5000 {
		return fmt.Errorf("store: sqlite busy_timeout is %d, expected 5000", busyTimeout)
	}
	return nil
}

// Ping checks that the database is reachable, for the readiness endpoint.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return d.PingContext(ctx)
}

// Close shuts the pool down, waiting for in-flight queries to finish.
func (d *DB) Close() error {
	if d.DB == nil {
		return nil
	}
	return d.DB.Close()
}
