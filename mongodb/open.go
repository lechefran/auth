// Package mongodb provides MongoDB migration helpers for auth stores.
package mongodb

import (
	"context"
	"errors"
	"strings"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Open opens a MongoDB database and verifies connectivity.
func Open(ctx context.Context, uri string, databaseName string) (*mongo.Database, error) {
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
	return client.Database(databaseName), nil
}
