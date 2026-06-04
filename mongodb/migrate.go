package mongodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lechefran/auth/migrate"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const (
	// PrincipalsCollection is the MongoDB collection for auth principals.
	PrincipalsCollection = "auth_principals"

	// APIKeysCollection is the MongoDB collection for API key metadata.
	APIKeysCollection = "auth_api_keys"

	// AuditEventsCollection is the MongoDB collection for audit events.
	AuditEventsCollection = "auth_audit_events"

	// SchemaMigrationsCollection is the MongoDB collection for migration records.
	SchemaMigrationsCollection = "auth_schema_migrations"

	migrationOperation = "mongodb:create_indexes"
)

// Migrations returns the MongoDB migrations for the auth adapter.
//
// MongoDB collections are created lazily. This migration creates the adapter
// indexes if needed and records the applied version.
func Migrations() []migrate.Migration {
	return []migrate.Migration{
		{
			Version: 1,
			Name:    "create_principals_api_keys_and_audit_event_indexes",
			SQL:     []string{migrationOperation},
		},
	}
}

// Migrate applies pending MongoDB migrations.
func Migrate(ctx context.Context, db *mongo.Database) error {
	_, err := migrate.ApplyPending(ctx, NewMigrationDriver(db), Migrations())
	return err
}

// DeleteData deletes all auth adapter data while keeping MongoDB indexes and migration records.
//
// This is intentionally separate from Migrate so index creation stays
// non-destructive unless callers explicitly choose to delete data.
func DeleteData(ctx context.Context, db *mongo.Database) error {
	if db == nil {
		return errors.New("mongodb: database is required")
	}
	for _, collection := range []string{
		AuditEventsCollection,
		APIKeysCollection,
		PrincipalsCollection,
	} {
		if _, err := db.Collection(collection).DeleteMany(ctx, bson.D{}); err != nil {
			return fmt.Errorf("delete %s data: %w", collection, err)
		}
	}
	return nil
}

// MigrationDriver implements migrate.Driver for MongoDB.
type MigrationDriver struct {
	db *mongo.Database
}

// NewMigrationDriver creates a MongoDB migration driver.
func NewMigrationDriver(db *mongo.Database) *MigrationDriver {
	return &MigrationDriver{db: db}
}

// EnsureSchema verifies the MongoDB database handle.
func (d *MigrationDriver) EnsureSchema(ctx context.Context) error {
	if d.db == nil {
		return errors.New("mongodb: database is required")
	}
	return d.db.Client().Ping(ctx, nil)
}

// Applied returns migrations already applied, keyed by version.
func (d *MigrationDriver) Applied(ctx context.Context) (map[int64]migrate.AppliedMigration, error) {
	cursor, err := d.db.Collection(SchemaMigrationsCollection).Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	applied := make(map[int64]migrate.AppliedMigration)
	for cursor.Next(ctx) {
		var record migrationRecord
		if err := cursor.Decode(&record); err != nil {
			return nil, err
		}
		if record.Version <= 0 || strings.TrimSpace(record.Name) == "" || record.AppliedAt.IsZero() {
			return nil, errors.New("mongodb: invalid migration record")
		}
		applied[record.Version] = migrate.AppliedMigration{
			Version:   record.Version,
			Name:      record.Name,
			AppliedAt: record.AppliedAt,
		}
	}
	if err := cursor.Err(); err != nil {
		return nil, err
	}
	return applied, nil
}

// Apply creates MongoDB indexes and records the migration.
//
// MongoDB index creation is idempotent when names and definitions match. The
// migration record is written last so retries remain safe if recording fails.
func (d *MigrationDriver) Apply(ctx context.Context, migration migrate.Migration) error {
	if err := validateMongoMigration(migration); err != nil {
		return err
	}
	if err := createIndexes(ctx, d.db); err != nil {
		return err
	}
	_, err := d.db.Collection(SchemaMigrationsCollection).InsertOne(ctx, migrationRecord{
		ID:        migration.Version,
		Version:   migration.Version,
		Name:      migration.Name,
		AppliedAt: time.Now().UTC(),
	})
	return err
}

type migrationRecord struct {
	ID        int64     `bson:"_id"`
	Version   int64     `bson:"version"`
	Name      string    `bson:"name"`
	AppliedAt time.Time `bson:"applied_at"`
}

type indexSpec struct {
	Collection      string
	Name            string
	Keys            bson.D
	Unique          bool
	SimpleCollation bool
}

func createIndexes(ctx context.Context, db *mongo.Database) error {
	if db == nil {
		return errors.New("mongodb: database is required")
	}

	grouped := make(map[string][]mongo.IndexModel)
	for _, spec := range indexSpecs() {
		grouped[spec.Collection] = append(grouped[spec.Collection], spec.model())
	}
	for collection, models := range grouped {
		if _, err := db.Collection(collection).Indexes().CreateMany(ctx, models); err != nil {
			return fmt.Errorf("create %s indexes: %w", collection, err)
		}
	}
	return nil
}

func indexSpecs() []indexSpec {
	return []indexSpec{
		{
			Collection:      PrincipalsCollection,
			Name:            "auth_principals_type_id_unique",
			Keys:            bson.D{{Key: "type", Value: 1}, {Key: "id", Value: 1}},
			Unique:          true,
			SimpleCollation: true,
		},
		{
			Collection:      APIKeysCollection,
			Name:            "auth_api_keys_id_unique",
			Keys:            bson.D{{Key: "id", Value: 1}},
			Unique:          true,
			SimpleCollation: true,
		},
		{
			Collection:      APIKeysCollection,
			Name:            "auth_api_keys_prefix_unique",
			Keys:            bson.D{{Key: "prefix", Value: 1}},
			Unique:          true,
			SimpleCollation: true,
		},
		{
			Collection: APIKeysCollection,
			Name:       "auth_api_keys_hash_unique",
			Keys:       bson.D{{Key: "hash", Value: 1}},
			Unique:     true,
		},
		{
			Collection:      APIKeysCollection,
			Name:            "auth_api_keys_owner_created_id_idx",
			Keys:            bson.D{{Key: "owner_type", Value: 1}, {Key: "owner_id", Value: 1}, {Key: "created_at", Value: 1}, {Key: "id", Value: 1}},
			SimpleCollation: true,
		},
		{
			Collection:      AuditEventsCollection,
			Name:            "auth_audit_events_id_unique",
			Keys:            bson.D{{Key: "id", Value: 1}},
			Unique:          true,
			SimpleCollation: true,
		},
		{
			Collection: AuditEventsCollection,
			Name:       "auth_audit_events_occurred_idx",
			Keys:       bson.D{{Key: "occurred", Value: 1}},
		},
	}
}

func (s indexSpec) model() mongo.IndexModel {
	opts := options.Index().SetName(s.Name)
	if s.Unique {
		opts.SetUnique(true)
	}
	if s.SimpleCollation {
		opts.SetCollation(&options.Collation{Locale: "simple"})
	}
	return mongo.IndexModel{
		Keys:    s.Keys,
		Options: opts,
	}
}

func validateMongoMigration(migration migrate.Migration) error {
	if len(migration.SQL) != 1 || migration.SQL[0] != migrationOperation {
		return errors.New("mongodb: unsupported migration operation")
	}
	return nil
}

func collectionNames() []string {
	return []string{
		PrincipalsCollection,
		APIKeysCollection,
		AuditEventsCollection,
		SchemaMigrationsCollection,
	}
}

func validateCollectionName(name string) error {
	if strings.TrimSpace(name) == "" || strings.Contains(name, "$") || strings.HasPrefix(name, "system.") {
		return errors.New("mongodb: invalid collection name")
	}
	return nil
}
