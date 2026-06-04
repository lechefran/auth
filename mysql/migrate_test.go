package mysql

import (
	"strings"
	"testing"
	"time"

	"github.com/lechefran/auth/migrate"
)

var _ migrate.Driver = (*MigrationDriver)(nil)

func TestMigrationsAreNonDestructive(t *testing.T) {
	t.Parallel()

	for _, migration := range Migrations() {
		for _, stmt := range migration.SQL {
			upper := strings.ToUpper(stmt)
			for _, forbidden := range []string{"DROP TABLE", "TRUNCATE", "DELETE FROM"} {
				if strings.Contains(upper, forbidden) {
					t.Fatalf("migration %d contains destructive statement %q: %s", migration.Version, forbidden, stmt)
				}
			}
		}
	}
}

func TestMigrationsCreateTablesIfMissing(t *testing.T) {
	t.Parallel()

	sql := allMigrationSQL()
	for _, want := range []string{
		"CREATE TABLE IF NOT EXISTS auth_principals",
		"CREATE TABLE IF NOT EXISTS auth_api_keys",
		"CREATE TABLE IF NOT EXISTS auth_audit_events",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration SQL missing %q", want)
		}
	}
}

func TestMigrationsCreateIndexesInline(t *testing.T) {
	t.Parallel()

	sql := allMigrationSQL()
	for _, want := range []string{
		"UNIQUE KEY auth_api_keys_prefix_unique (prefix)",
		"UNIQUE KEY auth_api_keys_hash_unique (hash)",
		"KEY auth_api_keys_owner_created_id_idx (owner_type, owner_id, created_at, id)",
		"KEY auth_audit_events_occurred_idx (occurred)",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration SQL missing %q", want)
		}
	}
	if strings.Contains(sql, "CREATE INDEX") {
		t.Fatal("migration SQL should keep indexes inline for MySQL compatibility")
	}
}

func TestSchemaValidatorCoversCriticalColumnsAndIndexes(t *testing.T) {
	t.Parallel()

	columns := make(map[string]bool)
	for _, column := range expectedColumns() {
		columns[column.Table+"."+column.Name+":"+column.Type] = true
	}
	for _, want := range []string{
		"auth_api_keys.hash:varbinary",
		"auth_api_keys.prefix:varchar",
		"auth_api_keys.scopes:longtext",
		"auth_audit_events.metadata:longtext",
	} {
		if !columns[want] {
			t.Fatalf("schema validator missing column %q", want)
		}
	}

	indexes := make(map[string]expectedIndex)
	for _, index := range expectedIndexes() {
		indexes[index.Table+"."+index.Name] = index
	}
	for _, name := range []string{
		"auth_api_keys.auth_api_keys_prefix_unique",
		"auth_api_keys.auth_api_keys_hash_unique",
		"auth_api_keys.auth_api_keys_owner_created_id_idx",
	} {
		if _, ok := indexes[name]; !ok {
			t.Fatalf("schema validator missing index %q", name)
		}
	}
	if !indexes["auth_api_keys.auth_api_keys_hash_unique"].Unique {
		t.Fatal("hash index must be unique")
	}
}

func TestParseTime(t *testing.T) {
	t.Parallel()

	want := time.Date(2026, 6, 4, 12, 30, 15, 123456000, time.UTC)
	cases := map[string]struct {
		value any
		want  time.Time
	}{
		"time":     {value: want, want: want},
		"bytes":    {value: []byte("2026-06-04 12:30:15.123456"), want: want},
		"string":   {value: "2026-06-04 12:30:15.123456", want: want},
		"rfc3339":  {value: "2026-06-04T12:30:15.123456Z", want: want},
		"datetime": {value: "2026-06-04 12:30:15", want: time.Date(2026, 6, 4, 12, 30, 15, 0, time.UTC)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := parseTime(tc.value)
			if err != nil {
				t.Fatalf("parseTime() error = %v", err)
			}
			if !got.Equal(tc.want) {
				t.Fatalf("parseTime() = %v, want %v", got, tc.want)
			}
		})
	}
}

func allMigrationSQL() string {
	var builder strings.Builder
	for _, migration := range Migrations() {
		for _, stmt := range migration.SQL {
			builder.WriteString(stmt)
			builder.WriteByte('\n')
		}
	}
	return builder.String()
}
