package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

// SQLTxAdapter adapts a standard *sql.Tx to pgx's DBTX interface.
// This allows a single transaction abstraction (*sql.Tx) to work with both
// PostgreSQL (pgx) and SQLite (database/sql) generated code.
//
// It exists because the PostgreSQL sqlc layer targets pgx/v5 (whose DBTX
// interface *sql.Tx does not satisfy), while everything else in the store
// layer passes *sql.Tx around. Rather than forcing two transaction types
// through the repository interface, the postgres adapter wraps the *sql.Tx
// here.
type SQLTxAdapter struct {
	tx *sql.Tx
}

// NewSqlTxAdapter wraps tx so pgx-generated queries can run inside it.
func NewSqlTxAdapter(tx *sql.Tx) *SQLTxAdapter {
	return &SQLTxAdapter{tx: tx}
}

func (a *SQLTxAdapter) Exec(ctx context.Context, query string, args ...interface{}) (pgconn.CommandTag, error) {
	res, err := a.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	return pgconn.NewCommandTag(fmt.Sprintf("SELECT %d", rows)), nil
}

func (a *SQLTxAdapter) Query(ctx context.Context, query string, args ...interface{}) (pgx.Rows, error) {
	rows, err := a.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return &sqlRowsAdapter{rows: rows}, nil
}

func (a *SQLTxAdapter) QueryRow(ctx context.Context, query string, args ...interface{}) pgx.Row {
	return &sqlRowAdapter{row: a.tx.QueryRowContext(ctx, query, args...)}
}

// sqlRowsAdapter adapts *sql.Rows to the pgx.Rows interface.
type sqlRowsAdapter struct {
	rows *sql.Rows
}

func (r *sqlRowsAdapter) Close() {
	_ = r.rows.Close()
}

func (r *sqlRowsAdapter) Err() error {
	return r.rows.Err()
}

func (r *sqlRowsAdapter) Next() bool {
	return r.rows.Next()
}

func (r *sqlRowsAdapter) Scan(dest ...interface{}) error {
	return r.rows.Scan(dest...)
}

// Values returns the current row's values. database/sql has no equivalent, so
// it is implemented by scanning into fresh destinations. Each call re-reads
// the current row, matching pgx semantics closely enough for generated code.
func (r *sqlRowsAdapter) Values() ([]interface{}, error) {
	cols, err := r.rows.Columns()
	if err != nil {
		return nil, err
	}
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := r.rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	return vals, nil
}

// RawValues returns the current row as raw bytes. Values arrive from
// database/sql already decoded, so each value is formatted to its byte form.
func (r *sqlRowsAdapter) RawValues() [][]byte {
	cols, err := r.rows.Columns()
	if err != nil {
		return nil
	}
	vals := make([]interface{}, len(cols))
	ptrs := make([]interface{}, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if err := r.rows.Scan(ptrs...); err != nil {
		return nil
	}
	raw := make([][]byte, len(vals))
	for i, v := range vals {
		switch t := v.(type) {
		case nil:
			raw[i] = nil
		case []byte:
			raw[i] = t
		case string:
			raw[i] = []byte(t)
		default:
			raw[i] = []byte(fmt.Sprintf("%v", t))
		}
	}
	return raw
}

func (r *sqlRowsAdapter) CommandTag() pgconn.CommandTag {
	return pgconn.CommandTag{}
}

func (r *sqlRowsAdapter) FieldDescriptions() []pgconn.FieldDescription {
	cols, err := r.rows.Columns()
	if err != nil {
		return nil
	}
	fds := make([]pgconn.FieldDescription, len(cols))
	for i, c := range cols {
		fds[i] = pgconn.FieldDescription{Name: c}
	}
	return fds
}

func (r *sqlRowsAdapter) Conn() *pgx.Conn {
	return nil // adapted from sql.Tx, no underlying pgx.Conn
}

// TypeMap satisfies the pgx.Rows interface. There is no live connection
// behind this adapter, so decoding relies on database/sql's drivers.
func (r *sqlRowsAdapter) TypeMap() *pgtype.Map {
	return pgtype.NewMap()
}

// sqlRowAdapter adapts *sql.Row to the pgx.Row interface.
type sqlRowAdapter struct {
	row *sql.Row
}

func (r *sqlRowAdapter) Scan(dest ...interface{}) error {
	return r.row.Scan(dest...)
}
