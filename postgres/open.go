// Package postgres provides PostgreSQL migration helpers for auth stores.
package postgres

import (
	"context"
	"database/sql"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// Open opens a PostgreSQL database and verifies connectivity.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
