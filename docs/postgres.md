# PostgreSQL Integration

PostgreSQL is a native durable store adapter. `postgres.Store` implements:

- `auth.PrincipalStore`
- `auth.APIKeyStore`
- `auth.AuditStore`
- `auth.AtomicAPIKeyAuditStore`

Because the store supports transactions, create/revoke operations and their
audit events can be committed atomically when the same store is configured as
both `APIKeys` and `Audit`.

## Setup

```go
ctx := context.Background()

db, err := postgres.Open(ctx, dsn)
if err != nil {
	return err
}
defer db.Close()

if err := postgres.Migrate(ctx, db); err != nil {
	return err
}

store := postgres.NewStore(db)
```

`postgres.Migrate` creates missing auth tables/indexes and validates compatible
existing schema. It does not delete existing data.

## Service Configuration

```go
lookupKey, err := keys.GenerateHMACKey()
if err != nil {
	return err
}

service, err := auth.New(auth.Config{
	Issuer:          "my-api",
	KeyPrefix:       "ak",
	APIKeyTTL:       90 * 24 * time.Hour,
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

Generate `lookupKey` once, store it in secret management, and reload the same
value on every boot. Changing it makes existing API keys unverifiable.

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

Principals are stored in `auth_principals`.

## Create An API Key

```go
created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
	OwnerType: auth.PrincipalTypeUser,
	OwnerID:   "user_123",
	Name:      "dashboard key",
	Scopes:    []string{"reports:read"},
})
```

The returned raw key has this shape:

```text
ak_<public-id>.<secret>
```

Show `created.RawKey` once. Do not log it or store it.

## What PostgreSQL Stores

`auth_api_keys` stores:

- `id`: internal API key ID
- `issuer`: configured service issuer
- `prefix`: public lookup prefix, for example `ak_abc123`
- `name`: display name
- `owner_type`: `user` or `group`
- `owner_id`: principal ID
- `hash`: HMAC-SHA-256 of the full raw key, stored as `BYTEA`
- `scopes`: JSONB array of scopes
- `created_at`
- `expires_at`
- `revoked_at`
- `last_used_at`

The raw key is not stored.

`auth_audit_events` stores structured audit records for create, verify, failed
verify, and revoke events.

## Expiration

If `CreateAPIKeyRequest.ExpiresAt` is nil, expiration is:

```go
expiresAt := now.Add(config.APIKeyTTL)
```

If `APIKeyTTL` is not set, the default is 90 days. Explicit expiration must be
after the service clock's current time.

## Verify

```go
verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
	RawKey:         rawKeyFromHeader,
	RequiredScopes: []string{"reports:read"},
})
```

Verification:

1. Parses the public prefix.
2. Loads the stored key by `prefix`.
3. Computes HMAC-SHA-256 over the presented raw key.
4. Constant-time compares the computed hash with the stored hash.
5. Checks issuer, expiration, revocation, required scopes, and principal state.
6. Best-effort updates `last_used_at`.
7. Best-effort records an audit event.

## Revoke

```go
err := service.RevokeAPIKey(ctx, auth.RevokeAPIKeyRequest{
	APIKeyID: created.APIKey.ID,
})
```

PostgreSQL revocation sets `revoked_at`. Revoked keys fail verification with
`auth.ErrInvalidCredentials`. The Postgres store writes the revoke mutation and
audit event in one transaction when configured as both key and audit store.

## Delete Auth Data

```go
err := store.DeleteData(ctx)
// or:
err = postgres.DeleteData(ctx, db)
```

This clears auth rows while keeping schema and migration records.
