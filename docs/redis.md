# Redis Support

Redis is not currently a native durable API key store in this package.

The Redis package provides:

- `redis.Open`
- `redis.Migrate`
- `redis.MigrateNamespace`
- `redis.DeleteData`
- `redis.DeleteNamespaceData`
- `redis.DrainNamespaceData`

It does not implement:

- `auth.PrincipalStore`
- `auth.APIKeyStore`
- `auth.AuditStore`
- `auth.AtomicAPIKeyAuditStore`

## What Redis Does Today

Redis migrations record a namespace marker so Redis-backed auth-adjacent
features can have versioned setup later.

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

This does not connect Redis to Postgres, MySQL, SQLite, or MongoDB. Auth writes
do not automatically show up in Redis.

## Using Redis With A Native Store

If your app uses Postgres:

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
	Issuer:          "my-api",
	APIKeyLookupKey: lookupKey,
	Principals:      store,
	APIKeys:         store,
	Audit:           store,
})
```

All auth state is stored in Postgres:

- principals
- API key metadata
- HMAC lookup hashes
- expiration state
- revocation state
- audit events

Redis is not involved unless your application explicitly uses it for a separate
purpose such as rate limiting, request counters, short-lived caches, or custom
event fanout.

## Delete And Drain

Delete one bounded namespace scan pass:

```go
err := redis.DeleteNamespaceData(ctx, client, "prod")
```

For reset workflows, quiesce writers first and then drain until multiple scan
passes observe no matching keys:

```go
err := redis.DrainNamespaceData(ctx, client, "prod", redis.DrainOptions{
	EmptyPasses: 2,
	MaxPasses:   10,
})
```

`DrainNamespaceData` returns `redis.ErrNamespaceNotDrained` if keys continue to
appear through the configured pass limit.

## Security Position

Do not manually dual-write API key state to Redis unless you have a clear cache
invalidation and revocation strategy. A stale Redis cache can create security
bugs, especially after key revocation.

For now, use a native durable adapter as the source of truth:

- SQLite
- PostgreSQL
- MySQL/MariaDB
- MongoDB
