package migrate

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestPendingReturnsOnlyUnappliedMigrationsInOrder(t *testing.T) {
	t.Parallel()

	driver := newMemoryDriver()
	driver.applied[1] = AppliedMigration{Version: 1, Name: "create_users", AppliedAt: time.Now()}

	pending, err := Pending(context.Background(), driver, []Migration{
		{Version: 3, Name: "create_tokens", SQL: []string{"create table tokens"}},
		{Version: 1, Name: "create_users", SQL: []string{"create table users"}},
		{Version: 2, Name: "create_sessions", SQL: []string{"create table sessions"}},
	})
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}

	got := versions(pending)
	want := []int64{2, 3}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Pending() versions = %v, want %v", got, want)
	}
	if !driver.ensureCalled {
		t.Fatal("Pending() did not ensure migration schema")
	}
}

func TestApplyPendingAppliesMigrationsInOrder(t *testing.T) {
	t.Parallel()

	driver := newMemoryDriver()
	applied, err := ApplyPending(context.Background(), driver, []Migration{
		{Version: 2, Name: "two", SQL: []string{"two"}},
		{Version: 1, Name: "one", SQL: []string{"one"}},
	})
	if err != nil {
		t.Fatalf("ApplyPending() error = %v", err)
	}

	got := versions(applied)
	want := []int64{1, 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ApplyPending() versions = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(driver.appliedOrder, want) {
		t.Fatalf("driver applied order = %v, want %v", driver.appliedOrder, want)
	}
}

func TestApplyPendingReturnsAlreadyAppliedOnFailure(t *testing.T) {
	t.Parallel()

	driver := newMemoryDriver()
	driver.failVersion = 2

	applied, err := ApplyPending(context.Background(), driver, []Migration{
		{Version: 1, Name: "one", SQL: []string{"one"}},
		{Version: 2, Name: "two", SQL: []string{"two"}},
	})
	if err == nil {
		t.Fatal("ApplyPending() error = nil, want error")
	}

	got := versions(applied)
	want := []int64{1}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ApplyPending() applied = %v, want %v", got, want)
	}
}

func TestPendingRejectsDuplicateVersions(t *testing.T) {
	t.Parallel()

	_, err := Pending(context.Background(), newMemoryDriver(), []Migration{
		{Version: 1, Name: "one", SQL: []string{"one"}},
		{Version: 1, Name: "duplicate", SQL: []string{"duplicate"}},
	})
	if !errors.Is(err, ErrInvalidMigration) {
		t.Fatalf("Pending() error = %v, want ErrInvalidMigration", err)
	}
}

func TestPendingRejectsEmptySQL(t *testing.T) {
	t.Parallel()

	_, err := Pending(context.Background(), newMemoryDriver(), []Migration{
		{Version: 1, Name: "one", SQL: []string{" "}},
	})
	if !errors.Is(err, ErrInvalidMigration) {
		t.Fatalf("Pending() error = %v, want ErrInvalidMigration", err)
	}
}

func TestPendingRejectsUnknownAppliedMigration(t *testing.T) {
	t.Parallel()

	driver := newMemoryDriver()
	driver.applied[99] = AppliedMigration{Version: 99, Name: "missing"}

	_, err := Pending(context.Background(), driver, []Migration{
		{Version: 1, Name: "one", SQL: []string{"one"}},
	})
	if !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("Pending() error = %v, want ErrMigrationConflict", err)
	}
}

func TestPendingRejectsRenamedAppliedMigration(t *testing.T) {
	t.Parallel()

	driver := newMemoryDriver()
	driver.applied[1] = AppliedMigration{Version: 1, Name: "old_name"}

	_, err := Pending(context.Background(), driver, []Migration{
		{Version: 1, Name: "new_name", SQL: []string{"one"}},
	})
	if !errors.Is(err, ErrMigrationConflict) {
		t.Fatalf("Pending() error = %v, want ErrMigrationConflict", err)
	}
}

func versions(migrations []Migration) []int64 {
	versions := make([]int64, 0, len(migrations))
	for _, migration := range migrations {
		versions = append(versions, migration.Version)
	}
	return versions
}

type memoryDriver struct {
	ensureCalled bool
	applied      map[int64]AppliedMigration
	appliedOrder []int64
	failVersion  int64
}

func newMemoryDriver() *memoryDriver {
	return &memoryDriver{
		applied: make(map[int64]AppliedMigration),
	}
}

func (d *memoryDriver) EnsureSchema(context.Context) error {
	d.ensureCalled = true
	return nil
}

func (d *memoryDriver) Applied(context.Context) (map[int64]AppliedMigration, error) {
	applied := make(map[int64]AppliedMigration, len(d.applied))
	for version, migration := range d.applied {
		applied[version] = migration
	}
	return applied, nil
}

func (d *memoryDriver) Apply(_ context.Context, migration Migration) error {
	if migration.Version == d.failVersion {
		return errors.New("forced failure")
	}
	d.applied[migration.Version] = AppliedMigration{
		Version:   migration.Version,
		Name:      migration.Name,
		AppliedAt: time.Now(),
	}
	d.appliedOrder = append(d.appliedOrder, migration.Version)
	return nil
}
