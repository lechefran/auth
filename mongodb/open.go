// Package mongodb provides a native MongoDB adapter for auth stores.
package mongodb

import (
	"context"
	"errors"
	"strings"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Connection owns a MongoDB client opened by this package.
type Connection struct {
	client   *mongo.Client
	database *mongo.Database
}

// Client returns the underlying MongoDB client.
func (c *Connection) Client() *mongo.Client {
	if c == nil {
		return nil
	}
	return c.client
}

// Database returns the configured MongoDB database.
func (c *Connection) Database() *mongo.Database {
	if c == nil {
		return nil
	}
	return c.database
}

// Store returns a MongoDB auth store backed by the configured database.
func (c *Connection) Store() *Store {
	if c == nil {
		return nil
	}
	return NewStore(c.database)
}

// TransactionalStore returns a MongoDB auth store with transaction-backed
// key/audit operations.
func (c *Connection) TransactionalStore() *TransactionalStore {
	if c == nil {
		return nil
	}
	return NewTransactionalStore(c.database)
}

// Close disconnects the underlying MongoDB client.
func (c *Connection) Close(ctx context.Context) error {
	if c == nil || c.client == nil {
		return nil
	}
	return c.client.Disconnect(ctx)
}

// Migrate applies pending MongoDB migrations to the configured database.
func (c *Connection) Migrate(ctx context.Context) error {
	if c == nil {
		return errors.New("mongodb: connection is required")
	}
	return Migrate(ctx, c.database)
}

// DeleteData deletes all auth adapter data in the configured database.
func (c *Connection) DeleteData(ctx context.Context) error {
	if c == nil {
		return errors.New("mongodb: connection is required")
	}
	return DeleteData(ctx, c.database)
}

// Open opens a MongoDB connection and verifies connectivity.
func Open(ctx context.Context, uri string, databaseName string) (*Connection, error) {
	if strings.TrimSpace(databaseName) == "" {
		return nil, errors.New("mongodb: database name is required")
	}
	client, err := mongo.Connect(options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		client.Disconnect(ctx)
		return nil, err
	}
	return &Connection{
		client:   client,
		database: client.Database(databaseName),
	}, nil
}
