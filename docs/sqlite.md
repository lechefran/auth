# SQLite Integration

SQLite is a native durable store adapter. `sqlite.Store` implements:

- `auth.PrincipalStore`
- `auth.APIKeyStore`
- `auth.AuditStore`
- `auth.AtomicAPIKeyAuditStore`

SQLite is useful for local development, embedded applications, tests, and
single-node deployments.

## Setup

```go
ctx := context.Background()

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

`sqlite.Open` enables foreign keys and uses one open connection for SQLite
correctness.

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

## What SQLite Stores

`auth_api_keys` stores:

- `id`: internal API key ID
- `issuer`
- `prefix`
- `name`
- `owner_type`
- `owner_id`
- `hash`: HMAC-SHA-256 lookup hash
- `scopes`: JSON-encoded scope list
- `created_at`
- `expires_at`
- `revoked_at`
- `last_used_at`

The raw key is not stored.

`auth_audit_events` stores structured audit records with JSON-encoded metadata.

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

Verification rejects malformed, wrong-secret, expired, revoked, disabled-owner,
and missing-scope keys. Successful verification best-effort updates
`last_used_at`.

## Revoke

```go
err := service.RevokeAPIKey(ctx, auth.RevokeAPIKeyRequest{
	APIKeyID: created.APIKey.ID,
})
```

SQLite writes revocation and audit in one transaction when the same store is
configured as `APIKeys` and `Audit`.

## Delete Auth Data

```go
err := store.DeleteData(ctx)
// or:
err = sqlite.DeleteData(ctx, db)
```

This clears auth rows while keeping schema and migration records.
