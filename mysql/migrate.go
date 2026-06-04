package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lechefran/auth/migrate"
)

const dateTimeLayout = "2006-01-02 15:04:05.999999"

// ErrIncompatibleSchema reports an existing auth schema that cannot safely be
// used by the MySQL/MariaDB adapter.
var ErrIncompatibleSchema = errors.New("mysql: incompatible schema")

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
	if _, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations()); err != nil {
		return err
	}
	return ValidateSchema(ctx, db)
}

// ValidateSchema verifies that existing auth tables and indexes are compatible
// with the MySQL/MariaDB adapter.
func ValidateSchema(ctx context.Context, db *sql.DB) error {
	return validateSchema(ctx, db)
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
	if err := validateSchema(ctx, d.db); err != nil {
		return err
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
	rows, err := runner.QueryContext(ctx, `SELECT table_name, column_name, data_type, is_nullable
		FROM information_schema.columns
		WHERE table_schema = DATABASE()
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
		if err := rows.Scan(&table, &name, &dataType, &nullable); err != nil {
			return nil, fmt.Errorf("scan columns: %w", err)
		}
		if columns[table] == nil {
			columns[table] = make(map[string]actualColumn)
		}
		columns[table][name] = actualColumn{
			Type:    strings.ToLower(dataType),
			NotNull: strings.EqualFold(nullable, "NO"),
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect columns: %w", err)
	}
	return columns, nil
}

func loadIndexes(ctx context.Context, runner schemaRunner) (map[string]map[string]actualIndex, error) {
	rows, err := runner.QueryContext(ctx, `SELECT table_name, index_name, non_unique, seq_in_index, column_name
		FROM information_schema.statistics
		WHERE table_schema = DATABASE()
			AND table_name IN ('auth_schema_migrations', 'auth_principals', 'auth_api_keys', 'auth_audit_events')
		ORDER BY table_name, index_name, seq_in_index`)
	if err != nil {
		return nil, fmt.Errorf("inspect indexes: %w", err)
	}
	defer rows.Close()

	indexes := make(map[string]map[string]actualIndex)
	for rows.Next() {
		var table string
		var name string
		var nonUnique int
		var seq int
		var column string
		if err := rows.Scan(&table, &name, &nonUnique, &seq, &column); err != nil {
			return nil, fmt.Errorf("scan indexes: %w", err)
		}
		if indexes[table] == nil {
			indexes[table] = make(map[string]actualIndex)
		}
		index := indexes[table][name]
		index.Unique = nonUnique == 0
		index.Columns = append(index.Columns, column)
		indexes[table][name] = index
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("inspect indexes: %w", err)
	}
	return indexes, nil
}

func expectedColumns() []expectedColumn {
	return []expectedColumn{
		{Table: "auth_schema_migrations", Name: "version", Type: "bigint", NotNull: true},
		{Table: "auth_schema_migrations", Name: "name", Type: "varchar", NotNull: true},
		{Table: "auth_schema_migrations", Name: "applied_at", Type: "datetime", NotNull: true},
		{Table: "auth_principals", Name: "type", Type: "varchar", NotNull: true},
		{Table: "auth_principals", Name: "id", Type: "varchar", NotNull: true},
		{Table: "auth_principals", Name: "name", Type: "varchar", NotNull: true},
		{Table: "auth_principals", Name: "created_at", Type: "datetime", NotNull: true},
		{Table: "auth_principals", Name: "updated_at", Type: "datetime", NotNull: true},
		{Table: "auth_principals", Name: "disabled_at", Type: "datetime"},
		{Table: "auth_api_keys", Name: "id", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "issuer", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "prefix", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "name", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "owner_type", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "owner_id", Type: "varchar", NotNull: true},
		{Table: "auth_api_keys", Name: "hash", Type: "varbinary", NotNull: true},
		{Table: "auth_api_keys", Name: "scopes", Type: "longtext", NotNull: true},
		{Table: "auth_api_keys", Name: "created_at", Type: "datetime", NotNull: true},
		{Table: "auth_api_keys", Name: "expires_at", Type: "datetime"},
		{Table: "auth_api_keys", Name: "revoked_at", Type: "datetime"},
		{Table: "auth_api_keys", Name: "last_used_at", Type: "datetime"},
		{Table: "auth_audit_events", Name: "id", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "type", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "actor_id", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "principal_type", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "principal_id", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "api_key_id", Type: "varchar", NotNull: true},
		{Table: "auth_audit_events", Name: "occurred", Type: "datetime", NotNull: true},
		{Table: "auth_audit_events", Name: "metadata", Type: "longtext", NotNull: true},
	}
}

func expectedIndexes() []expectedIndex {
	return []expectedIndex{
		{Table: "auth_schema_migrations", Name: "PRIMARY", Columns: []string{"version"}, Unique: true},
		{Table: "auth_principals", Name: "PRIMARY", Columns: []string{"type", "id"}, Unique: true},
		{Table: "auth_api_keys", Name: "PRIMARY", Columns: []string{"id"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_prefix_unique", Columns: []string{"prefix"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_hash_unique", Columns: []string{"hash"}, Unique: true},
		{Table: "auth_api_keys", Name: "auth_api_keys_owner_created_id_idx", Columns: []string{"owner_type", "owner_id", "created_at", "id"}},
		{Table: "auth_audit_events", Name: "PRIMARY", Columns: []string{"id"}, Unique: true},
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
