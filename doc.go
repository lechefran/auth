// Package auth provides database-independent API key workflows for users and
// groups.
//
// The service generates raw API keys, stores only HMAC-SHA-256 lookup hashes,
// verifies credentials, checks required scopes, revokes keys, lists keys with
// cursor pagination, and records structured audit events. Applications provide
// storage through small interfaces, or use an included native store adapter.
//
// # Key generation and service setup
//
// Generate the API key lookup key once, store it in secret management, and load
// it at process startup. Do not generate a new lookup key on every boot unless
// you intentionally want existing API keys to stop verifying.
//
//	lookupKey, err := keys.GenerateHMACKey()
//	if err != nil {
//		return err
//	}
//
//	service, err := auth.New(auth.Config{
//		Issuer:          "example-api",
//		KeyPrefix:       "ak",
//		APIKeyLookupKey: lookupKey,
//		Principals:      principalStore,
//		APIKeys:         apiKeyStore,
//		Audit:           auditStore,
//	})
//	if err != nil {
//		return err
//	}
//
// # Create and verify API keys
//
// API keys can be owned by users or groups. RawKey is returned once and must not
// be logged or stored.
//
//	created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
//		OwnerType: auth.PrincipalTypeUser,
//		OwnerID:   "user_123",
//		Name:      "production client",
//		Scopes:    []string{"widgets:read", "widgets:write"},
//	})
//	if err != nil {
//		return err
//	}
//
//	rawKey := created.RawKey
//
//	verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
//		RawKey:         rawKey,
//		RequiredScopes: []string{"widgets:read"},
//	})
//	if err != nil {
//		return err
//	}
//
//	_ = verified.Principal
//
// Revoke and list API keys
//
//	err := service.RevokeAPIKey(ctx, auth.RevokeAPIKeyRequest{
//		APIKeyID: verified.APIKey.ID,
//	})
//	if err != nil {
//		return err
//	}
//
//	page, err := service.ListAPIKeys(ctx, auth.ListAPIKeysRequest{
//		OwnerType: auth.PrincipalTypeUser,
//		OwnerID:   "user_123",
//		Page: auth.PageRequest{
//			Limit: 50,
//		},
//	})
//	if err != nil {
//		return err
//	}
//
//	if page.HasMore() {
//		nextPage, err := service.ListAPIKeys(ctx, auth.ListAPIKeysRequest{
//			OwnerType: auth.PrincipalTypeUser,
//			OwnerID:   "user_123",
//			Page: auth.PageRequest{
//				Limit:  50,
//				Cursor: page.NextCursor,
//			},
//		})
//		_ = nextPage
//		_ = err
//	}
//
// # SQLite setup
//
// SQLite is the complete built-in store adapter. It implements PrincipalStore,
// APIKeyStore, AuditStore, and AtomicAPIKeyAuditStore.
//
//	db, err := sqlite.Open(ctx, "auth.db")
//	if err != nil {
//		return err
//	}
//	defer db.Close()
//
//	if err := sqlite.Migrate(ctx, db); err != nil {
//		return err
//	}
//
//	store := sqlite.NewStore(db)
//
//	service, err := auth.New(auth.Config{
//		Issuer:          "example-api",
//		APIKeyLookupKey: lookupKey,
//		Principals:      store,
//		APIKeys:         store,
//		Audit:           store,
//	})
//
// # MySQL and MariaDB setup
//
// The MySQL/MariaDB package currently provides migration, schema validation,
// open, and explicit delete helpers.
//
//	db, err := mysql.Open(ctx, dsn)
//	if err != nil {
//		return err
//	}
//	defer db.Close()
//
//	if err := mysql.Migrate(ctx, db); err != nil {
//		return err
//	}
//
//	if err := mysql.ValidateSchema(ctx, db); err != nil {
//		return err
//	}
//
// # PostgreSQL setup
//
// PostgreSQL is a complete built-in store adapter. It implements PrincipalStore,
// APIKeyStore, AuditStore, and AtomicAPIKeyAuditStore.
//
//	db, err := postgres.Open(ctx, dsn)
//	if err != nil {
//		return err
//	}
//	defer db.Close()
//
//	if err := postgres.Migrate(ctx, db); err != nil {
//		return err
//	}
//
//	if err := postgres.ValidateSchema(ctx, db); err != nil {
//		return err
//	}
//
//	store := postgres.NewStore(db)
//
//	service, err := auth.New(auth.Config{
//		Issuer:          "example-api",
//		APIKeyLookupKey: lookupKey,
//		Principals:      store,
//		APIKeys:         store,
//		Audit:           store,
//	})
//
// # Redis setup
//
// Redis support currently covers namespaced migration markers and explicit
// namespace deletion helpers.
//
//	client, err := redis.Open(ctx, &goredis.Options{
//		Addr: "127.0.0.1:6379",
//	})
//	if err != nil {
//		return err
//	}
//	defer client.Close()
//
//	if err := redis.MigrateNamespace(ctx, client, "prod"); err != nil {
//		return err
//	}
//
//	// For reset workflows, quiesce writers before draining.
//	err = redis.DrainNamespaceData(ctx, client, "prod", redis.DrainOptions{
//		EmptyPasses: 2,
//		MaxPasses:   10,
//	})
//
// # MongoDB setup
//
// MongoDB support currently covers index migrations, simple collation for string
// identity indexes, a closeable connection helper, and explicit data deletion.
//
//	conn, err := mongodb.Open(ctx, uri, "auth")
//	if err != nil {
//		return err
//	}
//	defer conn.Close(ctx)
//
//	if err := conn.Migrate(ctx); err != nil {
//		return err
//	}
//
//	db := conn.Database()
//	_ = db
//
// If your application already owns the MongoDB client, pass its database handle
// directly:
//
//	db := client.Database("auth")
//	err := mongodb.Migrate(ctx, db)
//
// # Custom stores
//
// To use another database, implement PrincipalStore, APIKeyStore, and optionally
// AuditStore. Stores must never persist raw API keys. Store APIKey.Hash exactly
// as provided, index by APIKey.Prefix, return ErrNotFound for missing records,
// and return ErrAlreadyExists for uniqueness conflicts. If key metadata and
// audit events live in the same database, implement AtomicAPIKeyAuditStore so
// create and revoke operations can commit their audit event atomically.
package auth
