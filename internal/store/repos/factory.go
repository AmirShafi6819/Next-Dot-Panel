package repos

import (
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ashaibery/Next-Dot-Panel/internal/config"
	pg "github.com/ashaibery/Next-Dot-Panel/internal/store/postgres"
	lite "github.com/ashaibery/Next-Dot-Panel/internal/store/sqlite"
)

// NewQueries builds the dialect-neutral query surface from the raw handles a
// store.DB already owns.
//
// The arguments are primitives rather than a store.DB so this package does not
// gain a dependency on the store package for construction; the caller (the
// process wiring) passes db.Driver, db.DB and db.PGXPool().
func NewQueries(driver string, sqlDB *sql.DB, pool *pgxpool.Pool) (Queries, error) {
	switch driver {
	case config.DriverSQLite:
		if sqlDB == nil {
			return nil, fmt.Errorf("repos: sqlite handle is required")
		}
		return NewSQLiteQueries(lite.New(sqlDB)), nil
	case config.DriverPostgres:
		if pool == nil {
			return nil, fmt.Errorf("repos: postgres pool is required")
		}
		return NewPostgresQueries(pg.New(pool)), nil
	default:
		return nil, fmt.Errorf("repos: unsupported driver %q", driver)
	}
}
