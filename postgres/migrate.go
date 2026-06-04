package postgres

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
// used by the PostgreSQL adapter.
var ErrIncompatibleSchema = errors.New("postgres: incompatible schema")

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
	if _, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations()); err != nil {
		return err
	}
	return ValidateSchema(ctx, db)
}

// ValidateSchema verifies that existing auth tables and indexes are compatible
// with the PostgreSQL adapter.
func ValidateSchema(ctx context.Context, db *sql.DB) error {
	return validateSchema(ctx, db)
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
	if err := validateSchema(ctx, tx); err != nil {
		return err
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

type schemaRunner interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

type expectedColumn struct {
	Table   string
	Name    string
	Type    string
	NotNull bool
}

type expectedIndex struct {
	Table   string
	Name    string
	Columns []string
	Unique  bool
}

type actualColumn struct {
	Type    string
	NotNull bool
}

type actualIndex struct {
	Unique  bool
	Columns []string
}

func validateSchema(ctx context.Context, runner schemaRunner) error {
	columns, err := loadColumns(ctx, runner)
	if err != nil {
		return err
	}
	for _, want := range expectedColumns() {
		tableColumns := columns[want.Table]
		if len(tableColumns) == 0 {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing table %s", want.Table))
		}
		got, ok := tableColumns[want.Name]
		if !ok {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing column %s.%s", want.Table, want.Name))
		}
		if got.Type != want.Type {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("column %s.%s type = %q, want %q", want.Table, want.Name, got.Type, want.Type))
		}
		if want.NotNull && !got.NotNull {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("column %s.%s must be NOT NULL", want.Table, want.Name))
		}
	}

	indexes, err := loadIndexes(ctx, runner)
	if err != nil {
		return err
	}
	for _, want := range expectedIndexes() {
		got, ok := indexes[want.Table][want.Name]
		if !ok {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("missing index %s.%s", want.Table, want.Name))
		}
		if want.Unique && !got.Unique {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("index %s.%s must be unique", want.Table, want.Name))
		}
		if !equalStrings(got.Columns, want.Columns) {
			return errors.Join(ErrIncompatibleSchema, fmt.Errorf("index %s.%s columns = %v, want %v", want.Table, want.Name, got.Columns, want.Columns))
		}
	}
	return nil
}

func loadColumns(ctx context.Context, runner schemaRunner) (map[string]map[string]actualColumn, error) {
	rows, err := runner.QueryContext(ctx, `SELECT table_name, column_name, data_type, is_nullable, udt_name
		FROM information_schema.columns
		WHERE table_schema = current_schema()
			AND table_name IN ('auth_schema_migrations', 'auth_principals', 'auth_api_keys', 'auth_audit_events')`)
	if err != nil {
		return nil, fmt.Errorf("inspect columns: %w", err)
	}
	defer rows.Close()

	columns := make(map[string]map[string]actualColumn)
	for rows.Next() {
		var table string
		var name string
		var dataType string
		var nullable string
		var udtName string
		if err := rows.Scan(&table, &name, &dataType, &nullable, &udtName); err != nil {
			return nil, fmt.Errorf("scan columns: %w", err)
		}
		if columns[table] == nil {
			columns[table] = make(map[string]actualColumn)
		}
		columns[table][name] = actualColumn{
			Type:    normalizeColumnType(dataType, udtName),
			NotNull: strings.EqualFold(nullable, "NO"),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect columns: %w", err)
	}
	return columns, nil
}

func loadIndexes(ctx context.Context, runner schemaRunner) (map[string]map[string]actualIndex, error) {
	rows, err := runner.QueryContext(ctx, `SELECT table_name, index_name, is_unique, column_name
		FROM (
			SELECT
				t.relname AS table_name,
				i.relname AS index_name,
				ix.indisunique AS is_unique,
				a.attname AS column_name,
				k.ord AS column_order
			FROM pg_class t
			JOIN pg_namespace n ON n.oid = t.relnamespace
			JOIN pg_index ix ON ix.indrelid = t.oid
			JOIN pg_class i ON i.oid = ix.indexrelid
			JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON true
			JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = k.attnum
			WHERE n.nspname = current_schema()
				AND t.relname IN ('auth_schema_migrations', 'auth_principals', 'auth_api_keys', 'auth_audit_events')
		) indexed_columns
		ORDER BY table_name, index_name, column_order`)
	if err != nil {
		return nil, fmt.Errorf("inspect indexes: %w", err)
	}
	defer rows.Close()

	indexes := make(map[string]map[string]actualIndex)
	for rows.Next() {
		var table string
		var name string
		var unique bool
		var column string
		if err := rows.Scan(&table, &name, &unique, &column); err != nil {
			return nil, fmt.Errorf("scan indexes: %w", err)
		}
		if indexes[table] == nil {
			indexes[table] = make(map[string]actualIndex)
		}
		index := indexes[table][name]
		index.Unique = unique
		index.Columns = append(index.Columns, column)
		indexes[table][name] = index
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect indexes: %w", err)
	}
	return indexes, nil
}

func normalizeColumnType(dataType string, udtName string) string {
	if udtName == "timestamptz" {
		return "timestamptz"
	}
	return strings.ToLower(udtName)
}

func expectedColumns() []expectedColumn {
	return []expectedColumn{
		{Table: "auth_schema_migrations", Name: "version", Type: "int8", NotNull: true},
		{Table: "auth_schema_migrations", Name: "name", Type: "text", NotNull: true},
		{Table: "auth_schema_migrations", Name: "applied_at", Type: "timestamptz", NotNull: true},
		{Table: "auth_principals", Name: "type", Type: "text", NotNull: true},
		{Table: "auth_principals", Name: "id", Type: "text", NotNull: true},
		{Table: "auth_principals", Name: "name", Type: "text", NotNull: true},
		{Table: "auth_principals", Name: "created_at", Type: "timestamptz", NotNull: true},
		{Table: "auth_principals", Name: "updated_at", Type: "timestamptz", NotNull: true},
		{Table: "auth_principals", Name: "disabled_at", Type: "timestamptz"},
		{Table: "auth_api_keys", Name: "id", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "issuer", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "prefix", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "name", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "owner_type", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "owner_id", Type: "text", NotNull: true},
		{Table: "auth_api_keys", Name: "hash", Type: "bytea", NotNull: true},
		{Table: "auth_api_keys", Name: "scopes", Type: "jsonb", NotNull: true},
		{Table: "auth_api_keys", Name: "created_at", Type: "timestamptz", NotNull: true},
		{Table: "auth_api_keys", Name: "expires_at", Type: "timestamptz"},
		{Table: "auth_api_keys", Name: "revoked_at", Type: "timestamptz"},
		{Table: "auth_api_keys", Name: "last_used_at", Type: "timestamptz"},
		{Table: "auth_audit_events", Name: "id", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "type", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "actor_id", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "principal_type", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "principal_id", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "api_key_id", Type: "text", NotNull: true},
		{Table: "auth_audit_events", Name: "occurred", Type: "timestamptz", NotNull: true},
		{Table: "auth_audit_events", Name: "metadata", Type: "jsonb", NotNull: true},
	}
}

func expectedIndexes() []expectedIndex {
	return []expectedIndex{
		{Table: "auth_schema_migrations", Name: "auth_schema_migrations_pkey", Columns: []string{"version"}, Unique: true},
		{Table: "auth_principals", Name: "auth_principals_pkey", Columns: []string{"type", "id"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_pkey", Columns: []string{"id"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_prefix_unique", Columns: []string{"prefix"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_hash_unique", Columns: []string{"hash"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_owner_created_id_idx", Columns: []string{"owner_type", "owner_id", "created_at", "id"}},
		{Table: "auth_audit_events", Name: "auth_audit_events_pkey", Columns: []string{"id"}, Unique: true},
		{Table: "auth_audit_events", Name: "auth_audit_events_occurred_idx", Columns: []string{"occurred"}},
	}
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
