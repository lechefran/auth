package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/lechefran/auth/migrate"
)

const dateTimeLayout = "2006-01-02 15:04:05.999999"

// Migrations returns the MySQL/MariaDB schema migrations for the auth adapter.
func Migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version: 1,
			Name:    "create_principals_api_keys_and_audit_events",
			SQL: []string{
				`CREATE TABLE IF NOT EXISTS auth_principals (
					type VARCHAR(16) NOT NULL,
					id VARCHAR(191) NOT NULL,
					name VARCHAR(255) NOT NULL DEFAULT '',
					created_at DATETIME(6) NOT NULL,
					updated_at DATETIME(6) NOT NULL,
					disabled_at DATETIME(6) NULL,
					CONSTRAINT auth_principals_type_chk CHECK (type IN ('user', 'group')),
					PRIMARY KEY (type, id)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
				`CREATE TABLE IF NOT EXISTS auth_api_keys (
					id VARCHAR(191) NOT NULL,
					issuer VARCHAR(255) NOT NULL,
					prefix VARCHAR(191) NOT NULL,
					name VARCHAR(255) NOT NULL DEFAULT '',
					owner_type VARCHAR(16) NOT NULL,
					owner_id VARCHAR(191) NOT NULL,
					hash VARBINARY(64) NOT NULL,
					scopes LONGTEXT NOT NULL,
					created_at DATETIME(6) NOT NULL,
					expires_at DATETIME(6) NULL,
					revoked_at DATETIME(6) NULL,
					last_used_at DATETIME(6) NULL,
					CONSTRAINT auth_api_keys_owner_type_chk CHECK (owner_type IN ('user', 'group')),
					PRIMARY KEY (id),
					UNIQUE KEY auth_api_keys_prefix_unique (prefix),
					UNIQUE KEY auth_api_keys_hash_unique (hash),
					KEY auth_api_keys_owner_created_id_idx (owner_type, owner_id, created_at, id),
					CONSTRAINT auth_api_keys_owner_fk
						FOREIGN KEY (owner_type, owner_id)
						REFERENCES auth_principals(type, id)
						ON UPDATE CASCADE
						ON DELETE RESTRICT
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
				`CREATE TABLE IF NOT EXISTS auth_audit_events (
					id VARCHAR(191) NOT NULL,
					type VARCHAR(64) NOT NULL,
					actor_id VARCHAR(191) NOT NULL DEFAULT '',
					principal_type VARCHAR(16) NOT NULL DEFAULT '',
					principal_id VARCHAR(191) NOT NULL DEFAULT '',
					api_key_id VARCHAR(191) NOT NULL DEFAULT '',
					occurred DATETIME(6) NOT NULL,
					metadata LONGTEXT NOT NULL,
					PRIMARY KEY (id),
					KEY auth_audit_events_occurred_idx (occurred)
				) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`,
			},
		},
	}
}

// Migrate applies pending MySQL/MariaDB migrations.
func Migrate(ctx context.Context, db *sql.DB) error {
	_, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations())
	return err
}

// DeleteData deletes all auth adapter data while keeping the MySQL/MariaDB schema.
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

// MigrationDriver implements migrate.Driver for MySQL and MariaDB.
type MigrationDriver struct {
	db *sql.DB
}

// NewMigrationDriver creates a MySQL/MariaDB migration driver.
func NewMigrationDriver(db *sql.DB) *MigrationDriver {
	return &MigrationDriver{db: db}
}

// EnsureSchema creates the migration metadata table if needed.
func (d *MigrationDriver) EnsureSchema(ctx context.Context) error {
	_, err := d.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS auth_schema_migrations (
		version BIGINT NOT NULL,
		name VARCHAR(255) NOT NULL,
		applied_at DATETIME(6) NOT NULL,
		PRIMARY KEY (version)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin`)
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

// Apply applies migration statements and records the migration.
//
// MySQL and MariaDB implicitly commit DDL, so schema statements cannot be made
// fully atomic. The migration SQL is non-destructive and idempotent to make
// retries safe if recording the migration fails after the schema is created.
func (d *MigrationDriver) Apply(ctx context.Context, migration migrate.Migration) error {
	for _, stmt := range migration.SQL {
		if _, err := d.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("execute statement: %w", err)
		}
	}
	_, err := d.db.ExecContext(
		ctx,
		`INSERT INTO auth_schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
		migration.Version,
		migration.Name,
		time.Now().UTC(),
	)
	return err
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
	for _, layout := range []string{dateTimeLayout, time.DateTime, time.RFC3339Nano} {
		if t, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("parse time %q", value)
}
