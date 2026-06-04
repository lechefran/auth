package postgres

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

func TestMigrationsCreateIndexesIfMissing(t *testing.T) {
	t.Parallel()

	sql := allMigrationSQL()
	for _, want := range []string{
		"CREATE UNIQUE INDEX IF NOT EXISTS auth_api_keys_prefix_unique",
		"CREATE UNIQUE INDEX IF NOT EXISTS auth_api_keys_hash_unique",
		"CREATE INDEX IF NOT EXISTS auth_api_keys_owner_created_id_idx",
		"CREATE INDEX IF NOT EXISTS auth_audit_events_occurred_idx",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration SQL missing %q", want)
		}
	}
}

func TestMigrationsUsePostgresTypes(t *testing.T) {
	t.Parallel()

	sql := allMigrationSQL()
	for _, want := range []string{
		"hash BYTEA NOT NULL",
		"scopes JSONB NOT NULL",
		"metadata JSONB NOT NULL",
		"created_at TIMESTAMPTZ NOT NULL",
	} {
		if !strings.Contains(sql, want) {
			t.Fatalf("migration SQL missing %q", want)
		}
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
		"bytes":    {value: []byte("2026-06-04T12:30:15.123456Z"), want: want},
		"string":   {value: "2026-06-04T12:30:15.123456Z", want: want},
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
