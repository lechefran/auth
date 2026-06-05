package mongodb

import (
	"context"
	"testing"
)

func TestOpenReturnsConnectionHandle(t *testing.T) {
	t.Parallel()

	var open func(context.Context, string, string) (*Connection, error) = Open
	if open == nil {
		t.Fatal("Open is nil")
	}
}

func TestOpenRejectsBlankDatabaseName(t *testing.T) {
	t.Parallel()

	connection, err := Open(context.Background(), "mongodb://127.0.0.1:1", " ")
	if err == nil {
		t.Fatal("Open() returned nil error")
	}
	if connection != nil {
		t.Fatal("Open() returned connection for blank database name")
	}
}

func TestConnectionNilMethodsAreSafe(t *testing.T) {
	t.Parallel()

	var connection *Connection
	if connection.Client() != nil {
		t.Fatal("nil connection returned client")
	}
	if connection.Database() != nil {
		t.Fatal("nil connection returned database")
	}
	if err := connection.Close(context.Background()); err != nil {
		t.Fatalf("nil connection Close() error = %v", err)
	}
}

func TestConnectionOperationsRequireConnection(t *testing.T) {
	t.Parallel()

	var connection *Connection
	if err := connection.Migrate(context.Background()); err == nil {
		t.Fatal("nil connection Migrate() returned nil error")
	}
	if err := connection.DeleteData(context.Background()); err == nil {
		t.Fatal("nil connection DeleteData() returned nil error")
	}
}
