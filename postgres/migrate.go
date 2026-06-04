package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lechefran/auth/migrate"
)

// Migrations returns the PostgreSQL schema migrations for the auth adapter.
func Migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version: 1,
			Name:    "create_principals_api_keys_and_audit_events",
			SQL: []string{
				`CREATE TABLE IF NOT EXISTS auth_principals (
					type TEXT NOT NULL,
					id TEXT NOT NULL,
					name TEXT NOT NULL DEFAULT '',
					created_at TIMESTAMPTZ NOT NULL,
					updated_at TIMESTAMPTZ NOT NULL,
					disabled_at TIMESTAMPTZ NULL,
					CONSTRAINT auth_principals_type_chk CHECK (type IN ('user', 'group')),
					PRIMARY KEY (type, id)
				)`,
				`CREATE TABLE IF NOT EXISTS auth_api_keys (
					id TEXT PRIMARY KEY,
					issuer TEXT NOT NULL,
					prefix TEXT NOT NULL,
					name TEXT NOT NULL DEFAULT '',
					owner_type TEXT NOT NULL,
					owner_id TEXT NOT NULL,
					hash BYTEA NOT NULL,
					scopes JSONB NOT NULL,
					created_at TIMESTAMPTZ NOT NULL,
					expires_at TIMESTAMPTZ NULL,
					revoked_at TIMESTAMPTZ NULL,
					last_used_at TIMESTAMPTZ NULL,
					CONSTRAINT auth_api_keys_owner_type_chk CHECK (owner_type IN ('user', 'group')),
					CONSTRAINT auth_api_keys_owner_fk
						FOREIGN KEY (owner_type, owner_id)
						REFERENCES auth_principals(type, id)
						ON UPDATE CASCADE
						ON DELETE RESTRICT
				)`,
				`CREATE UNIQUE INDEX IF NOT EXISTS auth_api_keys_prefix_unique
					ON auth_api_keys(prefix)`,
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
					occurred TIMESTAMPTZ NOT NULL,
					metadata JSONB NOT NULL
				)`,
				`CREATE INDEX IF NOT EXISTS auth_audit_events_occurred_idx
					ON auth_audit_events(occurred)`,
			},
		},
	}
}

// Migrate applies pending PostgreSQL migrations.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations())
	return err
}

// DeleteData deletes all auth adapter data while keeping the PostgreSQL schema.
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

// MigrationDriver implements migrate.Driver for PostgreSQL.
type MigrationDriver struct {
	db *sql.DB
}

// NewMigrationDriver creates a PostgreSQL migration driver.
func NewMigrationDriver(db *sql.DB) *MigrationDriver {
	return &MigrationDriver{db: db}
}

// EnsureSchema creates the migration metadata table if needed.
func (d *MigrationDriver) EnsureSchema(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_schema_migrations (
		version BIGINT PRIMARY KEY,
		name TEXT NOT NULL,
		applied_at TIMESTAMPTZ NOT NULL
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
		var appliedAt any
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
		`INSERT INTO auth_schema_migrations(version, name, applied_at) VALUES ($1, $2, $3)`,
		migration.Version,
		migration.Name,
		time.Now().UTC(),
	); err != nil {
		return err
	}
	return tx.Commit()
}

func parseTime(value any) (time.Time, error) {
	switch typed := value.(type) {
	case time.Time:
		return typed, nil
	case []byte:
		return parseTimeString(string(typed))
	case string:
		return parseTimeString(typed)
	default:
		return time.Time{}, fmt.Errorf("unsupported time value %T", value)
	}
}

func parseTimeString(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.DateTime} {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse time %q", value)
}
