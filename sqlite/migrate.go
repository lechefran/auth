// Package sqlite provides a SQLite adapter for auth stores.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lechefran/auth/migrate"
)

// ErrIncompatibleSchema reports an existing auth schema that cannot safely be
// used by the SQLite adapter.
var ErrIncompatibleSchema = errors.New("sqlite: incompatible schema")

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
	if _, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations()); err != nil {
		return err
	}
	return ValidateSchema(ctx, db)
}

// ValidateSchema verifies that existing auth tables and indexes are compatible
// with the SQLite adapter.
func ValidateSchema(ctx context.Context, db *sql.DB) error {
	return validateSchema(ctx, db)
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
	if err := validateSchema(ctx, tx); err != nil {
		return err
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

type schemaRunner interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type expectedColumn struct {
	Name    string
	Type    string
	NotNull bool
}

type expectedIndex struct {
	Table   string
	Columns []string
	Unique  bool
}

func validateSchema(ctx context.Context, runner schemaRunner) error {
	tables := map[string][]expectedColumn{
		"auth_schema_migrations": {
			{Name: "version", Type: "INTEGER"},
			{Name: "name", Type: "TEXT", NotNull: true},
			{Name: "applied_at", Type: "TEXT", NotNull: true},
		},
		"auth_principals": {
			{Name: "type", Type: "TEXT", NotNull: true},
			{Name: "id", Type: "TEXT", NotNull: true},
			{Name: "name", Type: "TEXT", NotNull: true},
			{Name: "created_at", Type: "TEXT", NotNull: true},
			{Name: "updated_at", Type: "TEXT", NotNull: true},
			{Name: "disabled_at", Type: "TEXT"},
		},
		"auth_api_keys": {
			{Name: "id", Type: "TEXT"},
			{Name: "issuer", Type: "TEXT", NotNull: true},
			{Name: "prefix", Type: "TEXT", NotNull: true},
			{Name: "name", Type: "TEXT", NotNull: true},
			{Name: "owner_type", Type: "TEXT", NotNull: true},
			{Name: "owner_id", Type: "TEXT", NotNull: true},
			{Name: "hash", Type: "BLOB", NotNull: true},
			{Name: "scopes", Type: "TEXT", NotNull: true},
			{Name: "created_at", Type: "TEXT", NotNull: true},
			{Name: "expires_at", Type: "TEXT"},
			{Name: "revoked_at", Type: "TEXT"},
			{Name: "last_used_at", Type: "TEXT"},
		},
		"auth_audit_events": {
			{Name: "id", Type: "TEXT"},
			{Name: "type", Type: "TEXT", NotNull: true},
			{Name: "actor_id", Type: "TEXT", NotNull: true},
			{Name: "principal_type", Type: "TEXT", NotNull: true},
			{Name: "principal_id", Type: "TEXT", NotNull: true},
			{Name: "api_key_id", Type: "TEXT", NotNull: true},
			{Name: "occurred", Type: "TEXT", NotNull: true},
			{Name: "metadata", Type: "TEXT", NotNull: true},
		},
	}
	for table, columns := range tables {
		if err := validateTableColumns(ctx, runner, table, columns); err != nil {
			return err
		}
	}

	for _, index := range []expectedIndex{
		{Table: "auth_api_keys", Columns: []string{"prefix"}, Unique: true},
		{Table: "auth_api_keys", Columns: []string{"hash"}, Unique: true},
		{Table: "auth_api_keys", Columns: []string{"owner_type", "owner_id", "created_at", "id"}},
		{Table: "auth_audit_events", Columns: []string{"occurred"}},
	} {
		if err := validateIndex(ctx, runner, index); err != nil {
			return err
		}
	}
	return nil
}

func validateTableColumns(ctx context.Context, runner schemaRunner, table string, expected []expectedColumn) error {
	rows, err := runner.QueryContext(ctx, `PRAGMA table_info(`+quoteSQLiteIdent(table)+`)`)
	if err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	defer rows.Close()

	actual := make(map[string]expectedColumn)
	for rows.Next() {
		var cid int
		var column expectedColumn
		var defaultValue sql.NullString
		var notNull int
		var pk int
		if err := rows.Scan(&cid, &column.Name, &column.Type, &notNull, &defaultValue, &pk); err != nil {
			return fmt.Errorf("scan %s columns: %w", table, err)
		}
		column.Type = strings.ToUpper(column.Type)
		column.NotNull = notNull == 1 || pk > 0
		actual[column.Name] = column
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("inspect %s columns: %w", table, err)
	}
	if len(actual) == 0 {
		return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing table %s", table))
	}

	for _, want := range expected {
		got, ok := actual[want.Name]
		if !ok {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing column %s.%s", table, want.Name))
		}
		if want.Type != "" && !strings.Contains(got.Type, want.Type) {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("column %s.%s type = %q, want %q", table, want.Name, got.Type, want.Type))
		}
		if want.NotNull && !got.NotNull {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("column %s.%s must be NOT NULL", table, want.Name))
		}
	}
	return nil
}

func validateIndex(ctx context.Context, runner schemaRunner, expected expectedIndex) error {
	indexes, err := listIndexes(ctx, runner, expected.Table)
	if err != nil {
		return err
	}
	for _, index := range indexes {
		if expected.Unique && !index.Unique {
			continue
		}
		if equalStrings(index.Columns, expected.Columns) {
			return nil
		}
	}
	return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing index on %s(%s)", expected.Table, strings.Join(expected.Columns, ", ")))
}

type sqliteIndex struct {
	Name    string
	Unique  bool
	Columns []string
}

func listIndexes(ctx context.Context, runner schemaRunner, table string) ([]sqliteIndex, error) {
	rows, err := runner.QueryContext(ctx, `PRAGMA index_list(`+quoteSQLiteIdent(table)+`)`)
	if err != nil {
		return nil, fmt.Errorf("inspect %s indexes: %w", table, err)
	}

	var indexes []sqliteIndex
	for rows.Next() {
		var seq int
		var index sqliteIndex
		var unique int
		var origin string
		var partial int
		if err := rows.Scan(&seq, &index.Name, &unique, &origin, &partial); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan %s indexes: %w", table, err)
		}
		index.Unique = unique == 1
		indexes = append(indexes, index)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("inspect %s indexes: %w", table, err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close %s indexes: %w", table, err)
	}

	for i := range indexes {
		indexes[i].Columns, err = indexColumns(ctx, runner, indexes[i].Name)
		if err != nil {
			return nil, err
		}
	}
	return indexes, nil
}

func indexColumns(ctx context.Context, runner schemaRunner, indexName string) ([]string, error) {
	rows, err := runner.QueryContext(ctx, `PRAGMA index_info(`+quoteSQLiteIdent(indexName)+`)`)
	if err != nil {
		return nil, fmt.Errorf("inspect %s columns: %w", indexName, err)
	}
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var seqno int
		var cid int
		var name string
		if err := rows.Scan(&seqno, &cid, &name); err != nil {
			return nil, fmt.Errorf("scan %s columns: %w", indexName, err)
		}
		columns = append(columns, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect %s columns: %w", indexName, err)
	}
	return columns, nil
}

func quoteSQLiteIdent(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func equalStrings(left []string, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}
