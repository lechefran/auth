# auth

`auth` is a Go package for issuing, verifying, listing, and revoking API keys
for users or groups. It is designed so applications can bring their own storage
while the package handles the security-sensitive workflow: API key generation,
HMAC lookup hashing, expiration, revocation, scope checks, pagination, and audit
events.

The package currently includes native SQLite, PostgreSQL, MySQL/MariaDB, and
MongoDB stores plus Redis schema marker helpers.

## Features

- API keys for `user` and `group` principals.
- Raw API keys are returned once and are never stored by the core service.
- Stored lookup hashes use HMAC-SHA-256 with an application-controlled secret key.
- Prefix lookup keeps verification efficient without storing raw keys.
- Default API key TTL is 90 days unless overridden.
- Scope checks are deny-by-default when required scopes are missing.
- Structured audit events for create, verify, failed verify, and revoke.
- Optional atomic key/audit writes through `AtomicAPIKeyAuditStore`.
- Cursor pagination with bounded page sizes.
- Non-destructive migrations that create missing tables/indexes only.
- Explicit delete helpers for callers that intentionally want to clear auth data.

## Install

```bash
go get github.com/lechefran/auth
```

## Quick Start With SQLite

SQLite, PostgreSQL, MySQL/MariaDB, and MongoDB are complete built-in store
adapters. They implement principal, API key, audit, pagination, and atomic
key/audit operations.

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	auth "github.com/lechefran/auth"
	"github.com/lechefran/auth/keys"
	"github.com/lechefran/auth/sqlite"
)

func main() {
	ctx := context.Background()

	db, err := sqlite.Open(ctx, "auth.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if err := sqlite.Migrate(ctx, db); err != nil {
		log.Fatal(err)
	}

	store := sqlite.NewStore(db)

	now := time.Now().UTC()
	err = store.CreatePrincipal(ctx, auth.Principal{
		ID:        "user_123",
		Type:      auth.PrincipalTypeUser,
		Name:      "Example User",
		CreatedAt: now,
		UpdatedAt: now,
	})
	if err != nil && !errors.Is(err, auth.ErrAlreadyExists) {
		log.Fatal(err)
	}

	lookupKey, err := keys.GenerateHMACKey()
	if err != nil {
		log.Fatal(err)
	}

	service, err := auth.New(auth.Config{
		Issuer:          "example-api",
		KeyPrefix:       "ak",
		APIKeyLookupKey: lookupKey,
		Principals:      store,
		APIKeys:         store,
		Audit:           store,
	})
	if err != nil {
		log.Fatal(err)
	}

	created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Name:      "local development",
		Scopes:    []string{"read:widgets", "write:widgets"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Show RawKey once to the caller. Do not log or store it.
	fmt.Println(created.RawKey)

	verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{"read:widgets"},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(verified.Principal.ID)
}
```

## Core API

Create a service with `auth.New`:

```go
service, err := auth.New(auth.Config{
	Issuer:          "billing-api",
	KeyPrefix:       "ak",
	APIKeyTTL:       30 * 24 * time.Hour,
	APIKeyLookupKey: lookupKey,
	Principals:      principalStore,
	APIKeys:         apiKeyStore,
	Audit:           auditStore,
})
```

Important configuration rules:

- `Issuer` is required and should be stable for a deployment.
- `APIKeyLookupKey` is required when `APIKeys` is configured. Load it from
  secret management; do not hard-code it.
- `KeyPrefix` defaults to `ak` and may contain ASCII letters, digits, and
  hyphens.
- `APIKeyTTL` defaults to 90 days.
- `Audit` is optional, but recommended for operational visibility.

Generate a lookup key:

```go
lookupKey, err := keys.GenerateHMACKey()
```

In production, generate this once and store it in a secret manager. Rotating it
without a migration strategy will make existing API key hashes unverifiable.

## Create, Verify, Revoke

```go
created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
	OwnerType: auth.PrincipalTypeGroup,
	OwnerID:   "group_ops",
	Name:      "deploy automation",
	Scopes:    []string{"deploy:read", "deploy:write"},
})
```

`created.RawKey` is the only copy of the credential. `created.APIKey.Hash` is
redacted from service results.

```go
verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
	RawKey:         rawKeyFromRequest,
	RequiredScopes: []string{"deploy:write"},
})
```

Verification rejects malformed keys, wrong secrets, expired keys, revoked keys,
disabled principals, and missing required scopes.

```go
err := service.RevokeAPIKey(ctx, auth.RevokeAPIKeyRequest{
	APIKeyID: verified.APIKey.ID,
})
```

Revocation flow:

- Callers revoke by stored `APIKey.ID`, not by raw API key.
- The store sets `RevokedAt`; the raw API key cannot verify after that point.
- Verification returns `auth.ErrInvalidCredentials` for revoked keys so callers
  do not learn whether the key was revoked, expired, missing, or malformed.
- Revoke returns store errors such as `auth.ErrNotFound` or
  `auth.ErrInvalidState` when the key does not exist or cannot transition.
- Revoke records `api_key.revoked` when an audit store is configured.

Atomic revoke behavior:

- If the same store value is configured as both `APIKeys` and `Audit`, and that
  store implements `AtomicAPIKeyAuditStore`, the service uses
  `RevokeAPIKeyWithAudit`.
- In that path, the store reads the key, revokes it, and writes the audit event
  in one store-owned atomic operation.
- If the stores are different values or the interface is not implemented, the
  service performs a normal read, revoke, and best-effort audit write.

SQLite implements the atomic path. Custom stores should implement
`AtomicAPIKeyAuditStore` when API key metadata and audit events live in the same
transactional database.

## Scope Enforcement

Scopes are simple strings attached to each API key at creation time. The service
normalizes scopes by trimming whitespace, rejects malformed scopes, and removes
duplicates.

```go
created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
	OwnerType: auth.PrincipalTypeUser,
	OwnerID:   "user_123",
	Name:      "read-only dashboard",
	Scopes:    []string{"reports:read"},
})
```

Enforce scopes during verification by passing `RequiredScopes`. Verification is
deny-by-default for requested permissions: every required scope must be present
on the API key.

```go
verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
	RawKey:         rawKeyFromRequest,
	RequiredScopes: []string{"reports:read"},
})
if errors.Is(err, auth.ErrPermissionDenied) {
	// The key is valid, but it does not have every required scope.
	return err
}
if err != nil {
	return err
}

_ = verified
```

Scope enforcement behavior:

- `RequiredScopes` empty means authentication only; no authorization scope is
  required by the service call.
- `RequiredScopes` non-empty requires every listed scope.
- Extra scopes on the key are allowed.
- Missing scopes return `auth.ErrPermissionDenied`.
- Missing-scope denials record `api_key.verification_failed` with
  `reason=missing_scope` when audit is configured.

## Pagination

List APIs use cursor pagination.

```go
page, err := service.ListAPIKeys(ctx, auth.ListAPIKeysRequest{
	OwnerType: auth.PrincipalTypeUser,
	OwnerID:   "user_123",
	Page: auth.PageRequest{
		Limit: 50,
	},
})
if err != nil {
	return err
}

for _, key := range page.Items {
	fmt.Println(key.ID, key.Name)
}

if page.HasMore() {
	nextPage, err := service.ListAPIKeys(ctx, auth.ListAPIKeysRequest{
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Page: auth.PageRequest{
			Limit:  50,
			Cursor: page.NextCursor,
		},
	})
	_ = nextPage
	_ = err
}
```

Defaults and limits:

- `Limit == 0` uses `auth.DefaultPageLimit` (`50`).
- Limits above `auth.MaxPageLimit` (`200`) are capped.
- Cursors are opaque. Pass them back unchanged.

## Storage Interfaces

Applications can supply their own database implementation by satisfying these
interfaces:

```go
type PrincipalStore interface {
	GetPrincipal(ctx context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error)
}

type APIKeyStore interface {
	CreateAPIKey(ctx context.Context, key auth.APIKey) error
	GetAPIKeyByID(ctx context.Context, keyID string) (auth.APIKey, error)
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (auth.APIKey, error)
	ListAPIKeys(ctx context.Context, ownerType auth.PrincipalType, ownerID string, page auth.PageRequest) (auth.Page[auth.APIKey], error)
	RevokeAPIKey(ctx context.Context, keyID string, revokedAt time.Time) error
	TouchAPIKey(ctx context.Context, keyID string, usedAt time.Time) error
}

type AuditStore interface {
	RecordAuditEvent(ctx context.Context, event auth.AuditEvent) error
}
```

Store implementation requirements:

- Never persist raw API keys.
- Index API keys by `Prefix`.
- Store `Hash` exactly as provided by the service.
- Return `auth.ErrNotFound` for missing rows/documents.
- Return `auth.ErrAlreadyExists` for duplicate IDs or unique prefixes.
- Make `TouchAPIKey` best-effort safe; verification does not fail if touch
  storage fails.
- Keep cursor ordering stable and deterministic.

## Native Adapter Setup

Adapter setup helpers are non-destructive. They create missing tables,
collections, indexes, or marker records only. Existing SQL schemas are
compatibility-checked before migrations are recorded.

### SQLite

```go
db, err := sqlite.Open(ctx, "auth.db")
if err != nil {
	return err
}
defer db.Close()

if err := sqlite.Migrate(ctx, db); err != nil {
	return err
}

store := sqlite.NewStore(db)
```

Clear auth data explicitly:

```go
err := sqlite.DeleteData(ctx, db)
// or:
err = store.DeleteData(ctx)
```

### MySQL / MariaDB

```go
db, err := mysql.Open(ctx, dsn)
if err != nil {
	return err
}
defer db.Close()

if err := mysql.Migrate(ctx, db); err != nil {
	return err
}

store := mysql.NewStore(db)

service, err := auth.New(auth.Config{
	Issuer:          "example-api",
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

Useful helpers:

```go
err := mysql.ValidateSchema(ctx, db)
err = mysql.DeleteData(ctx, db)
// or:
err = store.DeleteData(ctx)
```

### PostgreSQL

```go
db, err := postgres.Open(ctx, dsn)
if err != nil {
	return err
}
defer db.Close()

if err := postgres.Migrate(ctx, db); err != nil {
	return err
}

store := postgres.NewStore(db)

service, err := auth.New(auth.Config{
	Issuer:          "example-api",
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

Useful helpers:

```go
err := postgres.ValidateSchema(ctx, db)
err = postgres.DeleteData(ctx, db)
// or:
err = store.DeleteData(ctx)
```

### Redis

Redis migrations use namespaced marker keys. Redis does not currently provide a
full API key store adapter in this package.

```go
client, err := redis.Open(ctx, &goredis.Options{
	Addr: "127.0.0.1:6379",
})
if err != nil {
	return err
}
defer client.Close()

if err := redis.MigrateNamespace(ctx, client, "prod"); err != nil {
	return err
}
```

Delete auth data in a namespace:

```go
err := redis.DeleteNamespaceData(ctx, client, "prod")
```

For reset/shutdown workflows where writers have been quiesced, drain until
multiple scan passes observe no keys:

```go
err := redis.DrainNamespaceData(ctx, client, "prod", redis.DrainOptions{
	EmptyPasses: 2,
	MaxPasses:   10,
})
```

`DrainNamespaceData` is bounded. It returns `redis.ErrNamespaceNotDrained` if
keys continue to appear through the configured pass limit.

### MongoDB

MongoDB is a native store adapter. Migrations create indexes with simple
collation for string identity indexes. The default `mongodb.Store` uses normal
writes with best-effort audit. Use `mongodb.TransactionalStore` when you want
atomic create/revoke with audit and your MongoDB deployment supports
transactions.

```go
conn, err := mongodb.Open(ctx, uri, "auth")
if err != nil {
	return err
}
defer conn.Close(ctx)

if err := conn.Migrate(ctx); err != nil {
	return err
}

store := conn.Store()

service, err := auth.New(auth.Config{
	Issuer:          "example-api",
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

For transaction-backed audit:

```go
store := conn.TransactionalStore()
```

If your application already owns the MongoDB client:

```go
db := client.Database("auth")
if err := mongodb.Migrate(ctx, db); err != nil {
	return err
}

store := mongodb.NewStore(db)
// or, on a replica set / sharded cluster:
transactionalStore := mongodb.NewTransactionalStore(db)
```

Clear auth data explicitly:

```go
err := conn.DeleteData(ctx)
// or:
err = mongodb.DeleteData(ctx, db)
```

## Audit Behavior

Audit events are structured and must not include secrets. The service records:

- `api_key.created`
- `api_key.verified`
- `api_key.verification_failed`
- `api_key.revoked`

Failed verification audit events may include non-secret metadata such as the API
key prefix and denial reason. Scope denial records `reason=missing_scope`.

## Security Notes

- Treat raw API keys as bearer credentials.
- Never log `RawKey`, key hashes, lookup keys, database credentials, or private
  key material.
- Use TLS and authenticated connections for remote databases.
- Keep `APIKeyLookupKey` in secret management and load it at process startup.
- Use short, explicit scopes and check required scopes server-side.
- Quiesce writers before destructive delete/drain operations.
- Prefer stores that implement `AtomicAPIKeyAuditStore` when API key metadata
  and audit events live in the same database.

## Testing

Run:

```bash
go test ./...
```

See [TESTING.md](TESTING.md) for the package testing matrix and the rules for
keeping it current as behavior changes.
