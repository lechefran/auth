# auth Documentation

These guides explain how to wire `auth` into an application with each supported
backend.

## Native Store Adapters

- [SQLite](sqlite.md)
- [PostgreSQL](postgres.md)
- [MySQL / MariaDB](mysql.md)
- [MongoDB](mongodb.md)

Native store adapters can be used directly with `auth.New` as principal, API
key, and audit stores.

## Redis

- [Redis](redis.md)

Redis is currently namespace/schema marker support only. It is not a primary API
key store and is not automatically synchronized with any database adapter.

## Common Flow

All native store adapters follow the same application flow:

1. Open the database connection.
2. Run the adapter setup/migration helper.
3. Create the adapter store.
4. Load a stable `APIKeyLookupKey` from secret management.
5. Create `auth.Service` with the store wired as `Principals`, `APIKeys`, and
   usually `Audit`.
6. Create principals for users or groups that can own API keys.
7. Create API keys through `service.CreateAPIKey`.
8. Show `CreateAPIKeyResult.RawKey` once to the caller.
9. Verify request credentials through `service.VerifyAPIKey`.
10. Revoke by stored `APIKey.ID` through `service.RevokeAPIKey`.

Raw API keys are never stored by the package. Stores persist only metadata,
public prefixes, and HMAC-SHA-256 lookup hashes.
