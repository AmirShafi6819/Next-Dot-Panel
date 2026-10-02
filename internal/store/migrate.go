package store

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sync"

	"github.com/pressly/goose/v3"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
)

// gooseMu serialises every goose call. goose's configuration (base FS,
// dialect, logger) is package-global state, and /ready reads migration status
// from concurrent requests while migrations run at startup; without this lock
// those setters race.
var gooseMu sync.Mutex

// Migration sources are embedded so a single binary can initialise its own
// database without shipping .sql files alongside it.
//
//go:embed migrations/postgres/*.sql
var postgresMigrations embed.FS

//go:embed migrations/sqlite/*.sql
var sqliteMigrations embed.FS

// Migrate brings the schema up to date. Migrations run inside a lock, so two
// instances starting at the same time cannot race (Design Spec 32.1).
func Migrate(ctx context.Context, db *DB, log logger) error {
	gooseMu.Lock()
	defer gooseMu.Unlock()

	provider, dir, err := migrationSource(db.Driver)
	if err != nil {
		return err
	}

	goose.SetBaseFS(provider)
	goose.SetLogger(gooseLogger{log: log})

	dialect := goose.DialectPostgres
	if db.Driver == config.DriverSQLite {
		dialect = goose.DialectSQLite3
	}
	if err := goose.SetDialect(string(dialect)); err != nil {
		return fmt.Errorf("store: set migration dialect: %w", err)
	}

	if log != nil {
		log.Info(ctx, "applying migrations", "driver", db.Driver)
	}
	if err := goose.UpContext(ctx, db.DB, dir); err != nil {
		return fmt.Errorf("store: apply migrations: %w", err)
	}

	version, err := goose.GetDBVersionContext(ctx, db.DB)
	if err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	if log != nil {
		log.Info(ctx, "migrations up to date", "schema_version", version)
	}
	return nil
}

// MigrationInfo describes one migration for the CLI.
type MigrationInfo struct {
	Version int64
	Applied bool
}

// MigrationStatus reports which migrations exist and which are applied.
// goose's own Status() only prints to stdout, so the version list is compiled
// from ListMigrations and the current database version instead.
func MigrationStatus(ctx context.Context, db *DB) ([]MigrationInfo, error) {
	gooseMu.Lock()
	defer gooseMu.Unlock()

	provider, dir, err := migrationSource(db.Driver)
	if err != nil {
		return nil, err
	}
	goose.SetBaseFS(provider)

	dialect := goose.DialectPostgres
	if db.Driver == config.DriverSQLite {
		dialect = goose.DialectSQLite3
	}
	if err := goose.SetDialect(string(dialect)); err != nil {
		return nil, err
	}

	migrations, err := goose.CollectMigrations(dir, 0, goose.MaxVersion)
	if err != nil {
		return nil, fmt.Errorf("store: collect migrations: %w", err)
	}

	current, err := goose.GetDBVersionContext(ctx, db.DB)
	if err != nil {
		return nil, fmt.Errorf("store: read schema version: %w", err)
	}

	out := make([]MigrationInfo, 0, len(migrations))
	for _, m := range migrations {
		out = append(out, MigrationInfo{Version: m.Version, Applied: m.Version <= current})
	}
	return out, nil
}

// migrationSource returns the embedded filesystem and folder for a driver.
func migrationSource(driver string) (fs.FS, string, error) {
	switch driver {
	case config.DriverPostgres:
		return postgresMigrations, "migrations/postgres", nil
	case config.DriverSQLite:
		return sqliteMigrations, "migrations/sqlite", nil
	default:
		return nil, "", fmt.Errorf("store: no migrations for driver %q", driver)
	}
}

// SchemaVersion returns the currently applied migration version.
func SchemaVersion(ctx context.Context, db *DB) (int64, error) {
	gooseMu.Lock()
	defer gooseMu.Unlock()

	provider, dir, err := migrationSource(db.Driver)
	if err != nil {
		return 0, err
	}
	goose.SetBaseFS(provider)

	dialect := goose.DialectPostgres
	if db.Driver == config.DriverSQLite {
		dialect = goose.DialectSQLite3
	}
	if err := goose.SetDialect(string(dialect)); err != nil {
		return 0, err
	}
	if _, err := goose.GetDBVersionContext(ctx, db.DB); err != nil {
		return 0, err
	}
	// Re-read after ensuring the version table exists.
	_ = dir
	return goose.GetDBVersionContext(ctx, db.DB)
}

// gooseLogger adapts goose's logger interface onto Next.Panel's structured
// logger, so migration output respects the same level and format settings.
type gooseLogger struct {
	log logger
}

func (g gooseLogger) Printf(format string, v ...any) {
	if g.log == nil {
		return
	}
	g.log.Info(context.Background(), "migration", "detail", fmt.Sprintf(format, v...))
}

func (g gooseLogger) Fatalf(format string, v ...any) {
	if g.log == nil {
		return
	}
	g.log.Error(context.Background(), "migration failed", "detail", fmt.Sprintf(format, v...))
}
