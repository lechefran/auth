# MongoDB Integration

MongoDB is a native durable store adapter. The default `mongodb.Store`
implements:

- `auth.PrincipalStore`
- `auth.APIKeyStore`
- `auth.AuditStore`

`mongodb.TransactionalStore` additionally implements:

- `auth.AtomicAPIKeyAuditStore`

Use `TransactionalStore` only on MongoDB deployments that support transactions,
such as replica sets or sharded clusters. Standalone MongoDB deployments should
use `Store`.

## Setup

```go
ctx := context.Background()

conn, err := mongodb.Open(ctx, uri, "auth")
if err != nil {
	return err
}
defer conn.Close(ctx)

if err := conn.Migrate(ctx); err != nil {
	return err
}

store := conn.Store()
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
transactionalStore := mongodb.NewTransactionalStore(db)
_ = transactionalStore
```

## Service Configuration

```go
lookupKey, err := keys.GenerateHMACKey()
if err != nil {
	return err
}

service, err := auth.New(auth.Config{
	Issuer:          "my-api",
	KeyPrefix:       "ak",
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

Generate `lookupKey` once and keep it in secret management. Replacing it breaks
verification for existing API keys.

## Create A Principal

```go
now := time.Now().UTC()

err := store.CreatePrincipal(ctx, auth.Principal{
	ID:        "user_123",
	Type:      auth.PrincipalTypeUser,
	Name:      "Jane Doe",
	CreatedAt: now,
	UpdatedAt: now,
})
```

Principals are stored in the `auth_principals` collection.

## Create An API Key

```go
created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
	OwnerType: auth.PrincipalTypeUser,
	OwnerID:   "user_123",
	Name:      "dashboard key",
	Scopes:    []string{"reports:read"},
})
```

The raw key format is:

```text
ak_<public-id>.<secret>
```

Show `created.RawKey` once. Do not log it or store it.

## What MongoDB Stores

`auth_api_keys` stores:

- `_id`: internal API key ID
- `id`: internal API key ID
- `issuer`
- `prefix`
- `name`
- `owner_type`
- `owner_id`
- `hash`: HMAC-SHA-256 lookup hash as BSON binary data
- `scopes`: string array
- `created_at`
- `expires_at`
- `revoked_at`
- `last_used_at`

The raw key is not stored.

`auth_audit_events` stores structured audit records with metadata as a BSON
document. MongoDB migrations create simple-collation indexes for string identity
lookups.

## Expiration

If `CreateAPIKeyRequest.ExpiresAt` is nil, expiration is:

```go
expiresAt := now.Add(config.APIKeyTTL)
```

If `APIKeyTTL` is not set, the default is 90 days.

## Verify

```go
verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
	RawKey:         rawKeyFromHeader,
	RequiredScopes: []string{"reports:read"},
})
```

Verification computes an HMAC-SHA-256 lookup hash from the presented raw key,
compares it with the stored hash, checks issuer, expiration, revocation, scopes,
and principal state, then best-effort updates `last_used_at` and audit.

## Revoke

```go
err := service.RevokeAPIKey(ctx, auth.RevokeAPIKeyRequest{
	APIKeyID: created.APIKey.ID,
})
```

MongoDB revocation sets `revoked_at`. Revoked keys fail verification with
`auth.ErrInvalidCredentials`.

With `mongodb.TransactionalStore`, revocation and audit are written inside a
MongoDB transaction. With `mongodb.Store`, audit is best-effort after the
revocation mutation.

## Delete Auth Data

```go
err := store.DeleteData(ctx)
// or:
err = conn.DeleteData(ctx)
// or:
err = mongodb.DeleteData(ctx, db)
```

This clears auth documents while keeping indexes and migration records.
