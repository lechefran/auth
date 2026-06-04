// Package mysql provides MySQL and MariaDB migration helpers for auth stores.
package mysql

import (
	"context"
	"database/sql"

	_ "github.com/go-sql-driver/mysql"
)

// Open opens a MySQL or MariaDB database and verifies connectivity.
func Open(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
