package redis

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lechefran/auth/migrate"
)

var _ migrate.Driver = (*MigrationDriver)(nil)

func TestMigrationsAreNonDestructiveMarkers(t *testing.T) {
	t.Parallel()

	for _, migration := range Migrations() {
		if err := validateRedisMigration(migration); err != nil {
			t.Fatalf("validateRedisMigration() error = %v", err)
		}
		for _, stmt := range migration.SQL {
			upper := strings.ToUpper(stmt)
			for _, forbidden := range []string{"FLUSH", "DEL ", "UNLINK ", "KEYS "} {
				if strings.Contains(upper, forbidden) {
					t.Fatalf("migration %d contains destructive operation %q: %s", migration.Version, forbidden, stmt)
				}
			}
		}
	}
}

func TestNamespaceValidation(t *testing.T) {
	t.Parallel()

	for _, namespace := range []string{
		DefaultNamespace,
		"app-auth",
		"app_auth",
		"prod:auth",
		"tenant01:auth",
	} {
		if err := validateNamespace(namespace); err != nil {
			t.Fatalf("validateNamespace(%q) error = %v", namespace, err)
		}
	}

	for _, namespace := range []string{
		"",
		" auth",
		"auth ",
		"*",
		"auth*",
		"auth?",
		"auth[0]",
		":auth",
		"auth:",
		"auth::prod",
		"auth prod",
		strings.Repeat("a", maxNamespaceLength+1),
	} {
		if err := validateNamespace(namespace); !errors.Is(err, ErrInvalidNamespace) {
			t.Fatalf("validateNamespace(%q) error = %v, want ErrInvalidNamespace", namespace, err)
		}
	}
}

func TestRedisKeysAreNamespaced(t *testing.T) {
	t.Parallel()

	prefix, err := keyPrefix("prod:auth")
	if err != nil {
		t.Fatalf("keyPrefix() error = %v", err)
	}
	if prefix != "prod:auth:" {
		t.Fatalf("keyPrefix() = %q, want prod:auth:", prefix)
	}

	key, err := migrationsKey("prod:auth")
	if err != nil {
		t.Fatalf("migrationsKey() error = %v", err)
	}
	if key != "prod:auth:schema_migrations" {
		t.Fatalf("migrationsKey() = %q, want prod:auth:schema_migrations", key)
	}
}

func TestMigrationRecordRoundTrip(t *testing.T) {
	t.Parallel()

	want := migrationRecord{
		Name:      "record_auth_redis_namespace",
		AppliedAt: time.Date(2026, 6, 4, 12, 30, 15, 0, time.UTC),
	}
	encoded, err := encodeMigrationRecord(want)
	if err != nil {
		t.Fatalf("encodeMigrationRecord() error = %v", err)
	}
	got, err := decodeMigrationRecord(encoded)
	if err != nil {
		t.Fatalf("decodeMigrationRecord() error = %v", err)
	}
	if got.Name != want.Name || !got.AppliedAt.Equal(want.AppliedAt) {
		t.Fatalf("decoded record = %+v, want %+v", got, want)
	}
}

func TestDecodeMigrationRecordRejectsMalformedRecords(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		`not-json`,
		`{"name":"","applied_at":"2026-06-04T12:30:15Z"}`,
		`{"name":"record_auth_redis_namespace"}`,
	} {
		if _, err := decodeMigrationRecord(value); err == nil {
			t.Fatalf("decodeMigrationRecord(%q) returned nil error", value)
		}
	}
}
