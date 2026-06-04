package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	auth "github.com/lechefran/auth"
	"github.com/lechefran/auth/migrate"
)

var (
	_ auth.PrincipalStore         = (*Store)(nil)
	_ auth.APIKeyStore            = (*Store)(nil)
	_ auth.AuditStore             = (*Store)(nil)
	_ auth.AtomicAPIKeyAuditStore = (*Store)(nil)
	_ migrate.Driver              = (*MigrationDriver)(nil)
)

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openDB(t, ctx)
	defer db.Close()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() second run error = %v", err)
	}

	applied, err := NewMigrationDriver(db).Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != len(Migrations()) {
		t.Fatalf("applied migrations = %d, want %d", len(applied), len(Migrations()))
	}
}

func TestMigratePreservesExistingAuthTableData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openDB(t, ctx)
	defer db.Close()

	if _, err := db.ExecContext(ctx, Migrations()[0].SQL[0]); err != nil {
		t.Fatalf("create existing principals table error = %v", err)
	}
	now := fixedTime()
	if _, err := db.ExecContext(
		ctx,
		`INSERT INTO auth_principals(type, id, name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
		auth.PrincipalTypeUser,
		"user_existing",
		"Existing User",
		formatTime(now),
		formatTime(now),
	); err != nil {
		t.Fatalf("insert existing principal error = %v", err)
	}

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	got, err := NewStore(db).GetPrincipal(ctx, auth.PrincipalTypeUser, "user_existing")
	if err != nil {
		t.Fatalf("GetPrincipal() error = %v", err)
	}
	if got.Name != "Existing User" {
		t.Fatalf("GetPrincipal().Name = %q, want Existing User", got.Name)
	}
}

func TestMigrateRejectsIncompatibleExistingSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openDB(t, ctx)
	defer db.Close()

	if _, err := db.ExecContext(ctx, `CREATE TABLE auth_api_keys (
		id TEXT PRIMARY KEY,
		prefix TEXT NOT NULL UNIQUE,
		owner_type TEXT NOT NULL,
		owner_id TEXT NOT NULL,
		hash BLOB NOT NULL,
		created_at TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create incompatible table error = %v", err)
	}

	if err := Migrate(ctx, db); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("Migrate() error = %v, want ErrIncompatibleSchema", err)
	}
	applied, err := NewMigrationDriver(db).Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("applied migrations = %d, want 0", len(applied))
	}
}

func TestMigrateRejectsDriftedAppliedSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	db := openDB(t, ctx)
	defer db.Close()

	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX auth_api_keys_owner_created_id_idx`); err != nil {
		t.Fatalf("drop index error = %v", err)
	}
	if err := Migrate(ctx, db); !errors.Is(err, ErrIncompatibleSchema) {
		t.Fatalf("Migrate() after drift error = %v, want ErrIncompatibleSchema", err)
	}
}

func TestDeleteDataClearsAuthRowsAndKeepsSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.RecordAuditEvent(ctx, auth.AuditEvent{
		ID:            "event_1",
		Type:          auth.AuditEventAPIKeyCreated,
		ActorID:       "actor_1",
		PrincipalType: auth.PrincipalTypeUser,
		PrincipalID:   "user_123",
		APIKeyID:      "key_1",
		Occurred:      fixedTime(),
	}); err != nil {
		t.Fatalf("RecordAuditEvent() error = %v", err)
	}

	if err := store.DeleteData(ctx); err != nil {
		t.Fatalf("DeleteData() error = %v", err)
	}

	if _, err := store.GetPrincipal(ctx, auth.PrincipalTypeUser, "user_123"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("GetPrincipal() after DeleteData error = %v, want ErrNotFound", err)
	}
	if _, err := store.GetAPIKeyByID(ctx, "key_1"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("GetAPIKeyByID() after DeleteData error = %v, want ErrNotFound", err)
	}
	if got := countRows(t, ctx, store.db, "auth_audit_events"); got != 0 {
		t.Fatalf("audit rows after DeleteData = %d, want 0", got)
	}

	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_after_delete")
	afterDelete := testAPIKey("key_after_delete", "ak_after_delete", auth.PrincipalTypeUser, "user_after_delete", fixedTime())
	if err := store.CreateAPIKey(ctx, afterDelete); err != nil {
		t.Fatalf("CreateAPIKey() after DeleteData error = %v", err)
	}
}

func TestPrincipalStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	now := fixedTime()
	principal := auth.Principal{
		ID:        "user_123",
		Type:      auth.PrincipalTypeUser,
		Name:      "Test User",
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := store.CreatePrincipal(ctx, principal); err != nil {
		t.Fatalf("CreatePrincipal() error = %v", err)
	}
	got, err := store.GetPrincipal(ctx, auth.PrincipalTypeUser, "user_123")
	if err != nil {
		t.Fatalf("GetPrincipal() error = %v", err)
	}
	if got.ID != principal.ID || got.Type != principal.Type || got.Name != principal.Name {
		t.Fatalf("GetPrincipal() = %+v, want %+v", got, principal)
	}

	if err := store.CreatePrincipal(ctx, principal); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("CreatePrincipal() duplicate error = %v, want ErrAlreadyExists", err)
	}
	_, err = store.GetPrincipal(ctx, auth.PrincipalTypeUser, "missing")
	if !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("GetPrincipal() missing error = %v, want ErrNotFound", err)
	}
}

func TestAPIKeyStore(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())

	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	byID, err := store.GetAPIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID() error = %v", err)
	}
	byPrefix, err := store.GetAPIKeyByPrefix(ctx, key.Prefix)
	if err != nil {
		t.Fatalf("GetAPIKeyByPrefix() error = %v", err)
	}
	if byID.ID != key.ID || byPrefix.ID != key.ID {
		t.Fatalf("retrieved keys = %q/%q, want %q", byID.ID, byPrefix.ID, key.ID)
	}
	if !bytes.Equal(byID.Hash, key.Hash) {
		t.Fatal("GetAPIKeyByID() hash mismatch")
	}
	if len(byID.Scopes) != 2 {
		t.Fatalf("GetAPIKeyByID() scopes = %v, want 2 scopes", byID.Scopes)
	}

	byID.Hash[0] ^= 0xff
	again, err := store.GetAPIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID() error = %v", err)
	}
	if bytes.Equal(byID.Hash, again.Hash) {
		t.Fatal("GetAPIKeyByID() returned caller-owned hash slice")
	}
}

func TestCreateAPIKeyRejectsDuplicateAndMissingPrincipal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())

	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := store.CreateAPIKey(ctx, key); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("CreateAPIKey() duplicate error = %v, want ErrAlreadyExists", err)
	}

	missingOwner := testAPIKey("key_2", "ak_two", auth.PrincipalTypeUser, "missing", fixedTime())
	if err := store.CreateAPIKey(ctx, missingOwner); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("CreateAPIKey() missing owner error = %v, want ErrNotFound", err)
	}
}

func TestCreateAPIKeyWithAuditRollsBackWhenAuditFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	existingEvent := testAuditEvent("event_1", "existing_key")
	if err := store.RecordAuditEvent(ctx, existingEvent); err != nil {
		t.Fatalf("RecordAuditEvent() error = %v", err)
	}

	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())
	event := testAuditEvent("event_1", key.ID)
	if err := store.CreateAPIKeyWithAudit(ctx, key, event); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("CreateAPIKeyWithAudit() error = %v, want ErrAlreadyExists", err)
	}
	if _, err := store.GetAPIKeyByID(ctx, key.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("GetAPIKeyByID() after rollback error = %v, want ErrNotFound", err)
	}
}

func TestListAPIKeysPaginates(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	createPrincipal(t, ctx, store, auth.PrincipalTypeGroup, "group_123")
	base := fixedTime()
	for i := 0; i < 5; i++ {
		key := testAPIKey("key_"+string(rune('a'+i)), "ak_"+string(rune('a'+i)), auth.PrincipalTypeUser, "user_123", base.Add(time.Duration(i)*time.Second))
		if err := store.CreateAPIKey(ctx, key); err != nil {
			t.Fatalf("CreateAPIKey(%d) error = %v", i, err)
		}
	}
	if err := store.CreateAPIKey(ctx, testAPIKey("group_key", "ak_group", auth.PrincipalTypeGroup, "group_123", base)); err != nil {
		t.Fatalf("CreateAPIKey(group) error = %v", err)
	}

	first, err := store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{Limit: 2})
	if err != nil {
		t.Fatalf("ListAPIKeys(first) error = %v", err)
	}
	if len(first.Items) != 2 || first.Items[0].ID != "key_a" || first.Items[1].ID != "key_b" || !first.HasMore() {
		t.Fatalf("first page = %+v", first)
	}

	second, err := store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{Limit: 2, Cursor: first.NextCursor})
	if err != nil {
		t.Fatalf("ListAPIKeys(second) error = %v", err)
	}
	if len(second.Items) != 2 || second.Items[0].ID != "key_c" || second.Items[1].ID != "key_d" || !second.HasMore() {
		t.Fatalf("second page = %+v", second)
	}

	third, err := store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{Limit: 2, Cursor: second.NextCursor})
	if err != nil {
		t.Fatalf("ListAPIKeys(third) error = %v", err)
	}
	if len(third.Items) != 1 || third.Items[0].ID != "key_e" || third.HasMore() {
		t.Fatalf("third page = %+v", third)
	}
}

func TestListAPIKeysRejectsInvalidCursor(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)

	_, err := store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{
		Limit:  2,
		Cursor: "not-a-valid-cursor",
	})
	if !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("ListAPIKeys() error = %v, want ErrInvalidRequest", err)
	}
}

func TestListAPIKeysNormalizesPageWhenStoreCalledDirectly(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	if err := store.CreateAPIKey(ctx, testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	page, err := store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{})
	if err != nil {
		t.Fatalf("ListAPIKeys(default) error = %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("ListAPIKeys(default) returned %d items, want 1", len(page.Items))
	}

	_, err = store.ListAPIKeys(ctx, auth.PrincipalTypeUser, "user_123", auth.PageRequest{Limit: -1})
	if !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("ListAPIKeys(negative) error = %v, want ErrInvalidRequest", err)
	}
}

func TestRevokeAndTouchAPIKey(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	usedAt := fixedTime().Add(time.Hour)
	if err := store.TouchAPIKey(ctx, key.ID, usedAt); err != nil {
		t.Fatalf("TouchAPIKey() error = %v", err)
	}
	touched, err := store.GetAPIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID() error = %v", err)
	}
	if touched.LastUsedAt == nil || !touched.LastUsedAt.Equal(usedAt) {
		t.Fatalf("LastUsedAt = %v, want %v", touched.LastUsedAt, usedAt)
	}

	revokedAt := fixedTime().Add(2 * time.Hour)
	if err := store.RevokeAPIKey(ctx, key.ID, revokedAt); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	revoked, err := store.GetAPIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID() error = %v", err)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("RevokedAt = %v, want %v", revoked.RevokedAt, revokedAt)
	}
	if err := store.RevokeAPIKey(ctx, key.ID, revokedAt); !errors.Is(err, auth.ErrInvalidState) {
		t.Fatalf("RevokeAPIKey() second error = %v, want ErrInvalidState", err)
	}
	if err := store.TouchAPIKey(ctx, "missing", usedAt); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("TouchAPIKey() missing error = %v, want ErrNotFound", err)
	}
}

func TestRevokeAPIKeyWithAuditRollsBackWhenAuditFails(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	existingEvent := testAuditEvent("event_1", "existing_key")
	if err := store.RecordAuditEvent(ctx, existingEvent); err != nil {
		t.Fatalf("RecordAuditEvent() error = %v", err)
	}

	event := testAuditEvent("event_1", key.ID)
	if _, err := store.RevokeAPIKeyWithAudit(ctx, key.ID, fixedTime().Add(time.Hour), event); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("RevokeAPIKeyWithAudit() error = %v, want ErrAlreadyExists", err)
	}
	got, err := store.GetAPIKeyByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetAPIKeyByID() error = %v", err)
	}
	if got.RevokedAt != nil {
		t.Fatal("RevokeAPIKeyWithAudit() left key revoked after rollback")
	}
}

func TestRevokeAPIKeyWithAuditReturnsRevokedKeyMetadata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")
	key := testAPIKey("key_1", "ak_one", auth.PrincipalTypeUser, "user_123", fixedTime())
	if err := store.CreateAPIKey(ctx, key); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	revokedAt := fixedTime().Add(time.Hour)
	event := auth.AuditEvent{
		ID:       "event_1",
		Type:     auth.AuditEventAPIKeyRevoked,
		Occurred: fixedTime(),
	}
	revoked, err := store.RevokeAPIKeyWithAudit(ctx, key.ID, revokedAt, event)
	if err != nil {
		t.Fatalf("RevokeAPIKeyWithAudit() error = %v", err)
	}
	if revoked.ID != key.ID || revoked.OwnerID != key.OwnerID || revoked.OwnerType != key.OwnerType {
		t.Fatalf("revoked key = %+v, want original key owner metadata", revoked)
	}
	if revoked.RevokedAt == nil || !revoked.RevokedAt.Equal(revokedAt) {
		t.Fatalf("RevokedAt = %v, want %v", revoked.RevokedAt, revokedAt)
	}
}

func TestRecordAuditEvent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	event := auth.AuditEvent{
		ID:            "event_1",
		Type:          auth.AuditEventAPIKeyCreated,
		ActorID:       "actor_1",
		PrincipalType: auth.PrincipalTypeUser,
		PrincipalID:   "user_123",
		APIKeyID:      "key_1",
		Occurred:      fixedTime(),
		Metadata:      map[string]string{"reason": "test"},
	}
	if err := store.RecordAuditEvent(ctx, event); err != nil {
		t.Fatalf("RecordAuditEvent() error = %v", err)
	}
	if err := store.RecordAuditEvent(ctx, event); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("RecordAuditEvent() duplicate error = %v, want ErrAlreadyExists", err)
	}
}

func TestStoreWorksWithAuthService(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := newMigratedStore(t, ctx)
	createPrincipal(t, ctx, store, auth.PrincipalTypeUser, "user_123")

	service, err := auth.New(auth.Config{
		Issuer:          "test-issuer",
		APIKeyLookupKey: []byte("01234567890123456789012345678901"),
		Principals:      store,
		APIKeys:         store,
		Audit:           store,
	})
	if err != nil {
		t.Fatalf("auth.New() error = %v", err)
	}

	created, err := service.CreateAPIKey(ctx, auth.CreateAPIKeyRequest{
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Scopes:    []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if created.RawKey == "" {
		t.Fatal("CreateAPIKey() returned empty raw key")
	}

	verified, err := service.VerifyAPIKey(ctx, auth.VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("VerifyAPIKey() error = %v", err)
	}
	if verified.Principal.ID != "user_123" {
		t.Fatalf("verified principal = %q, want user_123", verified.Principal.ID)
	}

	page, err := service.ListAPIKeys(ctx, auth.ListAPIKeysRequest{
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Page:      auth.PageRequest{Limit: 1},
	})
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(page.Items) != 1 || page.Items[0].Hash != nil {
		t.Fatalf("ListAPIKeys() page = %+v, want one redacted key", page)
	}
}

func newMigratedStore(t *testing.T, ctx context.Context) *Store {
	t.Helper()

	db := openDB(t, ctx)
	t.Cleanup(func() {
		db.Close()
	})
	if err := Migrate(ctx, db); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return NewStore(db)
}

func openDB(t *testing.T, ctx context.Context) *sql.DB {
	t.Helper()

	db, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return db
}

func createPrincipal(t *testing.T, ctx context.Context, store *Store, principalType auth.PrincipalType, principalID string) {
	t.Helper()

	now := fixedTime()
	if err := store.CreatePrincipal(ctx, auth.Principal{
		ID:        principalID,
		Type:      principalType,
		Name:      principalID,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreatePrincipal() error = %v", err)
	}
}

func testAPIKey(id string, prefix string, ownerType auth.PrincipalType, ownerID string, createdAt time.Time) auth.APIKey {
	expiresAt := createdAt.Add(24 * time.Hour)
	return auth.APIKey{
		ID:        id,
		Issuer:    "test-issuer",
		Prefix:    prefix,
		Name:      id,
		OwnerType: ownerType,
		OwnerID:   ownerID,
		Hash:      []byte("hash-" + id),
		Scopes:    []string{"cards:read", "cards:write"},
		CreatedAt: createdAt,
		ExpiresAt: &expiresAt,
	}
}

func testAuditEvent(id string, keyID string) auth.AuditEvent {
	return auth.AuditEvent{
		ID:            id,
		Type:          auth.AuditEventAPIKeyCreated,
		ActorID:       "actor_1",
		PrincipalType: auth.PrincipalTypeUser,
		PrincipalID:   "user_123",
		APIKeyID:      keyID,
		Occurred:      fixedTime(),
		Metadata:      map[string]string{"reason": "test"},
	}
}

func countRows(t *testing.T, ctx context.Context, db *sql.DB, table string) int {
	t.Helper()

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table).Scan(&count); err != nil {
		t.Fatalf("count %s rows error = %v", table, err)
	}
	return count
}

func fixedTime() time.Time {
	return time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)
}
