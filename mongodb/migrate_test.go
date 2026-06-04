package mongodb

import (
	"strings"
	"testing"

	"github.com/lechefran/auth/migrate"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var _ migrate.Driver = (*MigrationDriver)(nil)

func TestMigrationsAreNonDestructiveIndexMarkers(t *testing.T) {
	t.Parallel()

	for _, migration := range Migrations() {
		if err := validateMongoMigration(migration); err != nil {
			t.Fatalf("validateMongoMigration() error = %v", err)
		}
		for _, stmt := range migration.SQL {
			upper := strings.ToUpper(stmt)
			for _, forbidden := range []string{"DROP", "DELETE", "REMOVE", "TRUNCATE"} {
				if strings.Contains(upper, forbidden) {
					t.Fatalf("migration %d contains destructive operation %q: %s", migration.Version, forbidden, stmt)
				}
			}
		}
	}
}

func TestCollectionNamesAreValid(t *testing.T) {
	t.Parallel()

	for _, name := range collectionNames() {
		if err := validateCollectionName(name); err != nil {
			t.Fatalf("validateCollectionName(%q) error = %v", name, err)
		}
	}
}

func TestIndexSpecsCoverAuthCollections(t *testing.T) {
	t.Parallel()

	collections := make(map[string]bool)
	for _, spec := range indexSpecs() {
		collections[spec.Collection] = true
	}
	for _, want := range []string{
		PrincipalsCollection,
		APIKeysCollection,
		AuditEventsCollection,
	} {
		if !collections[want] {
			t.Fatalf("index specs missing collection %q", want)
		}
	}
}

func TestIndexSpecsIncludeSecurityCriticalUniqueIndexes(t *testing.T) {
	t.Parallel()

	specs := specsByName()
	for _, name := range []string{
		"auth_principals_type_id_unique",
		"auth_api_keys_id_unique",
		"auth_api_keys_prefix_unique",
		"auth_api_keys_hash_unique",
		"auth_audit_events_id_unique",
	} {
		spec, ok := specs[name]
		if !ok {
			t.Fatalf("index specs missing %q", name)
		}
		if !spec.Unique {
			t.Fatalf("index %q Unique = false, want true", name)
		}
	}
}

func TestIndexSpecsUseSimpleCollationForStringIdentityIndexes(t *testing.T) {
	t.Parallel()

	specs := specsByName()
	for _, name := range []string{
		"auth_principals_type_id_unique",
		"auth_api_keys_id_unique",
		"auth_api_keys_prefix_unique",
		"auth_api_keys_owner_created_id_idx",
		"auth_audit_events_id_unique",
	} {
		spec, ok := specs[name]
		if !ok {
			t.Fatalf("index specs missing %q", name)
		}
		if !spec.SimpleCollation {
			t.Fatalf("index %q SimpleCollation = false, want true", name)
		}
	}
	if specs["auth_api_keys_hash_unique"].SimpleCollation {
		t.Fatal("hash index should not require string collation")
	}
}

func TestIndexModelAppliesSimpleCollation(t *testing.T) {
	t.Parallel()

	spec := specsByName()["auth_api_keys_prefix_unique"]
	model := spec.model()
	if model.Options == nil {
		t.Fatal("index model missing options")
	}
	indexOptions := &options.IndexOptions{}
	for _, setter := range model.Options.List() {
		if err := setter(indexOptions); err != nil {
			t.Fatalf("apply index option error = %v", err)
		}
	}
	if indexOptions.Collation == nil {
		t.Fatal("index model missing collation option")
	}
	if indexOptions.Collation.Locale != "simple" {
		t.Fatalf("collation locale = %q, want simple", indexOptions.Collation.Locale)
	}
}

func TestIndexSpecsIncludePaginationIndexes(t *testing.T) {
	t.Parallel()

	specs := specsByName()
	for _, name := range []string{
		"auth_api_keys_owner_created_id_idx",
		"auth_audit_events_occurred_idx",
	} {
		spec, ok := specs[name]
		if !ok {
			t.Fatalf("index specs missing %q", name)
		}
		if spec.Unique {
			t.Fatalf("index %q Unique = true, want false", name)
		}
	}
}

func TestIndexSpecNamesAreUnique(t *testing.T) {
	t.Parallel()

	seen := make(map[string]bool)
	for _, spec := range indexSpecs() {
		if seen[spec.Name] {
			t.Fatalf("duplicate index spec name %q", spec.Name)
		}
		seen[spec.Name] = true
	}
}

func specsByName() map[string]indexSpec {
	specs := make(map[string]indexSpec)
	for _, spec := range indexSpecs() {
		specs[spec.Name] = spec
	}
	return specs
}
