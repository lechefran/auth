package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lechefran/auth/migrate"
	goredis "github.com/redis/go-redis/v9"
)

const (
	// DefaultNamespace is the Redis key namespace used by Migrate and DeleteData.
	DefaultNamespace = "auth"

	maxNamespaceLength = 128
	scanBatchSize      = 500

	defaultDrainEmptyPasses = 2
	defaultDrainMaxPasses   = 10
)

// ErrInvalidNamespace reports a namespace that is unsafe for auth Redis keys.
var ErrInvalidNamespace = errors.New("redis: invalid namespace")

// ErrNamespaceNotDrained reports that Redis namespace deletion did not observe
// an empty namespace within the configured pass limit.
var ErrNamespaceNotDrained = errors.New("redis: namespace not drained")

// DrainOptions controls repeated Redis namespace deletion passes.
type DrainOptions struct {
	// EmptyPasses is the number of consecutive full scan passes that must find
	// no matching keys before deletion is considered complete. Defaults to 2.
	EmptyPasses int

	// MaxPasses is the maximum number of full scan passes before returning
	// ErrNamespaceNotDrained. Defaults to 10.
	MaxPasses int
}

// Migrations returns the Redis migrations for the auth adapter.
//
// Redis does not have tables to create. The migration is a no-op schema marker
// that records the adapter version in the configured namespace.
func Migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version: 1,
			Name:    "record_auth_redis_namespace",
			SQL:     []string{"redis:record_migration"},
		},
	}
}

// Migrate applies pending Redis migrations using DefaultNamespace.
func Migrate(ctx context.Context, client *goredis.Client) error {
	return MigrateNamespace(ctx, client, DefaultNamespace)
}

// MigrateNamespace applies pending Redis migrations in namespace.
func MigrateNamespace(ctx context.Context, client *goredis.Client, namespace string) error {
	_, err := migrate.ApplyPending(ctx, NewMigrationDriver(client, namespace), Migrations())
	return err
}

// DeleteData deletes all auth adapter data in DefaultNamespace.
func DeleteData(ctx context.Context, client *goredis.Client) error {
	return DeleteNamespaceData(ctx, client, DefaultNamespace)
}

// DeleteNamespaceData deletes all auth adapter data in namespace.
//
// This is intentionally separate from Migrate so namespace initialization stays
// non-destructive unless callers explicitly choose to delete data.
//
// This function performs one bounded SCAN pass. If writers may still be adding
// keys concurrently, use DrainNamespaceData after quiescing writers.
func DeleteNamespaceData(ctx context.Context, client *goredis.Client, namespace string) error {
	if client == nil {
		return errors.New("redis: client is required")
	}
	prefix, err := keyPrefix(namespace)
	if err != nil {
		return err
	}

	_, err = deleteNamespacePass(ctx, client, prefix)
	return err
}

// DrainNamespaceData repeatedly deletes auth adapter data in namespace until a
// configured number of consecutive scan passes observe no matching keys.
//
// This is intended for shutdown/reset workflows where callers can first
// quiesce writers. MaxPasses prevents unbounded looping if writers continue to
// create namespace keys during deletion.
func DrainNamespaceData(ctx context.Context, client *goredis.Client, namespace string, options DrainOptions) error {
	if client == nil {
		return errors.New("redis: client is required")
	}
	prefix, err := keyPrefix(namespace)
	if err != nil {
		return err
	}
	options, err = normalizeDrainOptions(options)
	if err != nil {
		return err
	}

	emptyPasses := 0
	for pass := 0; pass < options.MaxPasses; pass++ {
		deleted, err := deleteNamespacePass(ctx, client, prefix)
		if err != nil {
			return err
		}
		if deleted == 0 {
			emptyPasses++
			if emptyPasses >= options.EmptyPasses {
				return nil
			}
			continue
		}
		emptyPasses = 0
	}
	return ErrNamespaceNotDrained
}

func deleteNamespacePass(ctx context.Context, client *goredis.Client, prefix string) (int, error) {
	deleted := 0
	var cursor uint64
	for {
		keys, nextCursor, err := client.Scan(ctx, cursor, prefix+"*", scanBatchSize).Result()
		if err != nil {
			return 0, fmt.Errorf("scan auth namespace: %w", err)
		}
		if len(keys) > 0 {
			if err := client.Unlink(ctx, keys...).Err(); err != nil {
				return 0, fmt.Errorf("delete auth namespace data: %w", err)
			}
			deleted += len(keys)
		}
		cursor = nextCursor
		if cursor == 0 {
			return deleted, nil
		}
	}
}

// MigrationDriver implements migrate.Driver for Redis.
type MigrationDriver struct {
	client    *goredis.Client
	namespace string
}

// NewMigrationDriver creates a Redis migration driver.
func NewMigrationDriver(client *goredis.Client, namespace string) *MigrationDriver {
	return &MigrationDriver{client: client, namespace: namespace}
}

// EnsureSchema verifies the Redis client and namespace.
func (d *MigrationDriver) EnsureSchema(ctx context.Context) error {
	if d.client == nil {
		return errors.New("redis: client is required")
	}
	if _, err := keyPrefix(d.namespace); err != nil {
		return err
	}
	return d.client.Ping(ctx).Err()
}

// Applied returns migrations already applied, keyed by version.
func (d *MigrationDriver) Applied(ctx context.Context) (map[int64]migrate.AppliedMigration, error) {
	key, err := migrationsKey(d.namespace)
	if err != nil {
		return nil, err
	}
	records, err := d.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, err
	}

	applied := make(map[int64]migrate.AppliedMigration, len(records))
	for versionValue, recordValue := range records {
		version, err := strconv.ParseInt(versionValue, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse migration version %q: %w", versionValue, err)
		}
		record, err := decodeMigrationRecord(recordValue)
		if err != nil {
			return nil, err
		}
		applied[version] = migrate.AppliedMigration{
			Version:   version,
			Name:      record.Name,
			AppliedAt: record.AppliedAt,
		}
	}
	return applied, nil
}

// Apply records a Redis migration as applied.
func (d *MigrationDriver) Apply(ctx context.Context, migration migrate.Migration) error {
	if err := validateRedisMigration(migration); err != nil {
		return err
	}
	key, err := migrationsKey(d.namespace)
	if err != nil {
		return err
	}
	record, err := encodeMigrationRecord(migrationRecord{
		Name:      migration.Name,
		AppliedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	created, err := d.client.HSetNX(ctx, key, strconv.FormatInt(migration.Version, 10), record).Result()
	if err != nil {
		return err
	}
	if !created {
		return fmt.Errorf("redis: migration version %d is already recorded", migration.Version)
	}
	return nil
}

type migrationRecord struct {
	Name      string    `json:"name"`
	AppliedAt time.Time `json:"applied_at"`
}

func encodeMigrationRecord(record migrationRecord) (string, error) {
	raw, err := json.Marshal(record)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func decodeMigrationRecord(value string) (migrationRecord, error) {
	var record migrationRecord
	if err := json.Unmarshal([]byte(value), &record); err != nil {
		return migrationRecord{}, fmt.Errorf("decode migration record: %w", err)
	}
	if strings.TrimSpace(record.Name) == "" || record.AppliedAt.IsZero() {
		return migrationRecord{}, errors.New("redis: invalid migration record")
	}
	return record, nil
}

func validateRedisMigration(migration migrate.Migration) error {
	if len(migration.SQL) != 1 || migration.SQL[0] != "redis:record_migration" {
		return errors.New("redis: unsupported migration operation")
	}
	return nil
}

func normalizeDrainOptions(options DrainOptions) (DrainOptions, error) {
	if options.EmptyPasses == 0 {
		options.EmptyPasses = defaultDrainEmptyPasses
	}
	if options.MaxPasses == 0 {
		options.MaxPasses = defaultDrainMaxPasses
	}
	if options.EmptyPasses < 0 || options.MaxPasses < 0 {
		return DrainOptions{}, errors.New("redis: drain options must be non-negative")
	}
	if options.EmptyPasses == 0 || options.MaxPasses == 0 {
		return DrainOptions{}, errors.New("redis: drain options must be positive")
	}
	if options.EmptyPasses > options.MaxPasses {
		return DrainOptions{}, errors.New("redis: empty passes cannot exceed max passes")
	}
	return options, nil
}

func migrationsKey(namespace string) (string, error) {
	prefix, err := keyPrefix(namespace)
	if err != nil {
		return "", err
	}
	return prefix + "schema_migrations", nil
}

func keyPrefix(namespace string) (string, error) {
	if err := validateNamespace(namespace); err != nil {
		return "", err
	}
	return namespace + ":", nil
}

func validateNamespace(namespace string) error {
	if namespace == "" || len(namespace) > maxNamespaceLength || strings.TrimSpace(namespace) != namespace {
		return ErrInvalidNamespace
	}
	for _, r := range namespace {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == ':':
		default:
			return ErrInvalidNamespace
		}
	}
	if strings.HasPrefix(namespace, ":") || strings.HasSuffix(namespace, ":") || strings.Contains(namespace, "::") {
		return ErrInvalidNamespace
	}
	return nil
}
