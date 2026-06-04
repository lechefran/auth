// Package migrate provides explicit migration planning and execution.
package migrate

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

var (
	// ErrInvalidMigration reports malformed migration definitions.
	ErrInvalidMigration = errors.New("migrate: invalid migration")

	// ErrMigrationConflict reports conflicting migration history, such as an
	// applied version that is not present in the supplied migration list.
	ErrMigrationConflict = errors.New("migrate: migration conflict")
)

// Migration is a versioned schema change.
//
// SQL contains adapter-specific statements. The shared runner does not inspect
// or execute SQL directly; concrete database drivers decide how to apply each
// migration safely for their dialect.
type Migration struct {
	Version int64
	Name    string
	SQL     []string
}

// AppliedMigration records a migration already applied by a driver.
type AppliedMigration struct {
	Version   int64
	Name      string
	AppliedAt time.Time
}

// Driver owns dialect-specific migration storage and execution.
type Driver interface {
	// EnsureSchema creates the migration metadata table if needed.
	EnsureSchema(ctx context.Context) error

	// Applied returns migrations already applied, keyed by version.
	Applied(ctx context.Context) (map[int64]AppliedMigration, error)

	// Apply applies migration and records it as applied atomically.
	Apply(ctx context.Context, migration Migration) error
}

// Pending returns migrations that have not been applied yet.
func Pending(ctx context.Context, driver Driver, migrations []Migration) ([]Migration, error) {
	if driver == nil {
		return nil, errors.Join(ErrInvalidMigration, errors.New("driver is required"))
	}

	normalized, err := normalize(migrations)
	if err != nil {
		return nil, err
	}
	if err := driver.EnsureSchema(ctx); err != nil {
		return nil, fmt.Errorf("ensure migration schema: %w", err)
	}

	applied, err := driver.Applied(ctx)
	if err != nil {
		return nil, fmt.Errorf("load applied migrations: %w", err)
	}
	if err := validateApplied(normalized, applied); err != nil {
		return nil, err
	}

	pending := make([]Migration, 0, len(normalized))
	for _, migration := range normalized {
		if _, ok := applied[migration.Version]; !ok {
			pending = append(pending, migration)
		}
	}
	return pending, nil
}

// ApplyPending applies every pending migration in ascending version order.
func ApplyPending(ctx context.Context, driver Driver, migrations []Migration) ([]Migration, error) {
	pending, err := Pending(ctx, driver, migrations)
	if err != nil {
		return nil, err
	}

	applied := make([]Migration, 0, len(pending))
	for _, migration := range pending {
		if err := driver.Apply(ctx, migration); err != nil {
			return applied, fmt.Errorf("apply migration %d %s: %w", migration.Version, migration.Name, err)
		}
		applied = append(applied, migration)
	}
	return applied, nil
}

func normalize(migrations []Migration) ([]Migration, error) {
	normalized := append([]Migration(nil), migrations...)
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Version < normalized[j].Version
	})

	seen := make(map[int64]string, len(normalized))
	for _, migration := range normalized {
		if migration.Version <= 0 {
			return nil, errors.Join(ErrInvalidMigration, errors.New("version must be positive"))
		}
		if strings.TrimSpace(migration.Name) == "" {
			return nil, errors.Join(ErrInvalidMigration, fmt.Errorf("migration %d name is required", migration.Version))
		}
		if len(migration.SQL) == 0 {
			return nil, errors.Join(ErrInvalidMigration, fmt.Errorf("migration %d sql is required", migration.Version))
		}
		for _, statement := range migration.SQL {
			if strings.TrimSpace(statement) == "" {
				return nil, errors.Join(ErrInvalidMigration, fmt.Errorf("migration %d contains empty sql", migration.Version))
			}
		}
		if existing, ok := seen[migration.Version]; ok {
			return nil, errors.Join(ErrInvalidMigration, fmt.Errorf("duplicate version %d for %q and %q", migration.Version, existing, migration.Name))
		}
		seen[migration.Version] = migration.Name
	}

	return normalized, nil
}

func validateApplied(migrations []Migration, applied map[int64]AppliedMigration) error {
	known := make(map[int64]Migration, len(migrations))
	for _, migration := range migrations {
		known[migration.Version] = migration
	}

	for version, appliedMigration := range applied {
		migration, ok := known[version]
		if !ok {
			return errors.Join(ErrMigrationConflict, fmt.Errorf("applied version %d is not in migration list", version))
		}
		if appliedMigration.Name != "" && appliedMigration.Name != migration.Name {
			return errors.Join(ErrMigrationConflict, fmt.Errorf("applied version %d name %q does not match %q", version, appliedMigration.Name, migration.Name))
		}
	}
	return nil
}
