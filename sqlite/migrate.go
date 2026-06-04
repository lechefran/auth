// Package sqlite provides a SQLite adapter for auth stores.
package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lechefran/auth/migrate"
)

// Migrations returns the SQLite schema migrations for the auth adapter.
func Migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version: 1,
			Name:    "create_principals_api_keys_and_audit_events",
			SQL: []string{
				`CREATE TABLE IF NOT EXISTS auth_principals (
					type TEXT NOT NULL CHECK (type IN ('user', 'group')),
					id TEXT NOT NULL,
					name TEXT NOT NULL DEFAULT '',
					created_at TEXT NOT NULL,
					updated_at TEXT NOT NULL,
					disabled_at TEXT,
					PRIMARY KEY (type, id)
				)`,
				`CREATE TABLE IF NOT EXISTS auth_api_keys (
					id TEXT PRIMARY KEY,
					issuer TEXT NOT NULL,
					prefix TEXT NOT NULL UNIQUE,
					name TEXT NOT NULL DEFAULT '',
					owner_type TEXT NOT NULL CHECK (owner_type IN ('user', 'group')),
					owner_id TEXT NOT NULL,
					hash BLOB NOT NULL,
					scopes TEXT NOT NULL,
					created_at TEXT NOT NULL,
					expires_at TEXT,
					revoked_at TEXT,
					last_used_at TEXT,
					FOREIGN KEY (owner_type, owner_id)
						REFERENCES auth_principals(type, id)
						ON UPDATE CASCADE
						ON DELETE RESTRICT
				)`,
				`CREATE UNIQUE INDEX IF NOT EXISTS auth_api_keys_hash_unique
					ON auth_api_keys(hash)`,
				`CREATE INDEX IF NOT EXISTS auth_api_keys_owner_created_id_idx
					ON auth_api_keys(owner_type, owner_id, created_at, id)`,
				`CREATE TABLE IF NOT EXISTS auth_audit_events (
					id TEXT PRIMARY KEY,
					type TEXT NOT NULL,
					actor_id TEXT NOT NULL DEFAULT '',
					principal_type TEXT NOT NULL DEFAULT '',
					principal_id TEXT NOT NULL DEFAULT '',
					api_key_id TEXT NOT NULL DEFAULT '',
					occurred TEXT NOT NULL,
					metadata TEXT NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS auth_audit_events_occurred_idx
					ON auth_audit_events(occurred)`,
			},
		},
	}
}

// Migrate applies pending SQLite migrations.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations())
	return err
}

// DeleteData deletes all auth adapter data while keeping the SQLite schema.
//
// This is intentionally separate from Migrate so schema creation stays
// non-destructive unless callers explicitly choose to delete data.
func DeleteData(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range []string{
		`DELETE FROM auth_audit_events`,
		`DELETE FROM auth_api_keys`,
		`DELETE FROM auth_principals`,
	} {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("delete auth data: %w", err)
		}
	}
	return tx.Commit()
}

// MigrationDriver implements migrate.Driver for SQLite.
type MigrationDriver struct {
	db *sql.DB
}

// NewMigrationDriver creates a SQLite migration driver.
func NewMigrationDriver(db *sql.DB) *MigrationDriver {
	return &MigrationDriver{db: db}
}

// EnsureSchema creates the migration metadata table if needed.
func (d *MigrationDriver) EnsureSchema(ctx context.Context) error {
	if _, err := d.db.ExecContext(ctx, `PRAGMA foreign_keys = ON`); err != nil {
		return err
	}
	_, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_schema_migrations (
		version INTEGER PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TEXT NOT NULL
	)`)
	return err
}

// Applied returns migrations already applied, keyed by version.
func (d *MigrationDriver) Applied(ctx context.Context) (map[int64]migrate.AppliedMigration, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT version, name, applied_at FROM auth_schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int64]migrate.AppliedMigration)
	for rows.Next() {
		var migration migrate.AppliedMigration
		var appliedAt string
		if err := rows.Scan(&migration.Version, &migration.Name, &appliedAt); err != nil {
			return nil, err
		}
		migration.AppliedAt, err = parseTime(appliedAt)
		if err != nil {
			return nil, err
		}
		applied[migration.Version] = migration
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return applied, nil
}

// Apply applies migration and records it atomically.
func (d *MigrationDriver) Apply(ctx context.Context, migration migrate.Migration) error {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, stmt := range migration.SQL {
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}
	if _, err := tx.ExecContext(
		ctx,
		`INSERT INTO auth_schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
		migration.Version,
		migration.Name,
		formatTime(time.Now()),
	); err != nil {
		return err
	}
	return tx.Commit()
}
