package auth

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lechefran/auth/token"
)

func TestCreateAPIKeyStoresHashAndReturnsRawKeyOnce(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	result, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Name:      "CI key",
		Scopes:    []string{"cards:read", "cards:read", " cards:write "},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if result.RawKey == "" {
		t.Fatal("CreateAPIKey() returned empty raw key")
	}
	if !strings.HasPrefix(result.RawKey, result.APIKey.Prefix+".") {
		t.Fatalf("RawKey = %q, want prefix %q", result.RawKey, result.APIKey.Prefix+".")
	}
	if result.APIKey.Hash != nil {
		t.Fatal("CreateAPIKey() exposed lookup hash")
	}
	stored := store.apiKeys[result.APIKey.ID]
	if len(stored.Hash) == 0 {
		t.Fatal("CreateAPIKey() did not store lookup hash")
	}
	if bytes.Contains(stored.Hash, []byte(result.RawKey)) {
		t.Fatal("stored hash contains raw key material")
	}
	plainHash, err := token.LookupHash(result.RawKey)
	if err != nil {
		t.Fatalf("LookupHash() error = %v", err)
	}
	if bytes.Equal(stored.Hash, plainHash) {
		t.Fatal("stored hash used unkeyed sha256 lookup hash")
	}
	if len(result.APIKey.Scopes) != 2 {
		t.Fatalf("Scopes = %v, want normalized unique scopes", result.APIKey.Scopes)
	}
	if result.APIKey.ExpiresAt == nil {
		t.Fatal("CreateAPIKey() did not apply default expiration")
	}
	if len(store.apiKeys) != 1 {
		t.Fatalf("stored keys = %d, want 1", len(store.apiKeys))
	}
	if store.auditCount(AuditEventAPIKeyCreated) != 1 {
		t.Fatal("CreateAPIKey() did not record audit event")
	}
}

func TestCreateAPIKeyRejectsMalformedScopes(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	_, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Scopes:    []string{"cards:read", " "},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CreateAPIKey() error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateAPIKeyReturnsRawKeyWhenAuditFails(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	store.auditErr = errors.New("audit unavailable")

	result, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if result.RawKey == "" {
		t.Fatal("CreateAPIKey() returned empty raw key")
	}
	if _, ok := store.apiKeys[result.APIKey.ID]; !ok {
		t.Fatal("CreateAPIKey() did not store API key")
	}
}

func TestCreateAPIKeyRejectsMissingPrincipal(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	_, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeGroup,
		OwnerID:   "missing",
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CreateAPIKey() error = %v, want ErrInvalidRequest", err)
	}
}

func TestCreateAPIKeyRejectsDisabledPrincipal(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	disabledAt := time.Date(2026, 6, 3, 16, 1, 0, 0, time.UTC)
	store.principals[principalKey(PrincipalTypeGroup, "group_disabled")] = Principal{
		ID:         "group_disabled",
		Type:       PrincipalTypeGroup,
		Name:       "Disabled Group",
		CreatedAt:  disabledAt,
		UpdatedAt:  disabledAt,
		DisabledAt: &disabledAt,
	}

	_, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeGroup,
		OwnerID:   "group_disabled",
	})
	if !errors.Is(err, ErrDisabledPrincipal) {
		t.Fatalf("CreateAPIKey() error = %v, want ErrDisabledPrincipal", err)
	}
}

func TestVerifyAPIKeyReturnsPrincipalAndTouchesKey(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Scopes:    []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	verified, err := service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("VerifyAPIKey() error = %v", err)
	}

	if verified.Principal.ID != "user_123" {
		t.Fatalf("Principal.ID = %q, want user_123", verified.Principal.ID)
	}
	if verified.APIKey.LastUsedAt == nil {
		t.Fatal("VerifyAPIKey() did not touch key")
	}
	if verified.APIKey.Hash != nil {
		t.Fatal("VerifyAPIKey() exposed lookup hash")
	}
	if store.auditCount(AuditEventAPIKeyVerified) != 1 {
		t.Fatal("VerifyAPIKey() did not record audit event")
	}
}

func TestVerifyAPIKeyRejectsMalformedRequiredScopes(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Scopes:    []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	_, err = service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{" "},
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("VerifyAPIKey() error = %v, want ErrInvalidRequest", err)
	}
}

func TestVerifyAPIKeySucceedsWhenAuditFails(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	store.auditErr = errors.New("audit unavailable")
	verified, err := service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{RawKey: created.RawKey})
	if err != nil {
		t.Fatalf("VerifyAPIKey() error = %v", err)
	}
	if verified.APIKey.ID != created.APIKey.ID {
		t.Fatalf("VerifyAPIKey() ID = %q, want %q", verified.APIKey.ID, created.APIKey.ID)
	}
	if store.apiKeys[created.APIKey.ID].LastUsedAt == nil {
		t.Fatal("VerifyAPIKey() did not touch key")
	}
}

func TestVerifyAPIKeyRejectsWrongSecret(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	_, err = service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{
		RawKey: created.APIKey.Prefix + ".wrong",
	})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("VerifyAPIKey() error = %v, want ErrInvalidCredentials", err)
	}
	if store.auditCount(AuditEventAPIKeyVerificationFailed) != 1 {
		t.Fatal("VerifyAPIKey() did not record failure audit event")
	}
}

func TestVerifyAPIKeyRejectsMissingScope(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeGroup,
		OwnerID:   "group_123",
		Scopes:    []string{"cards:read"},
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	_, err = service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{"cards:write"},
	})
	if !errors.Is(err, ErrPermissionDenied) {
		t.Fatalf("VerifyAPIKey() error = %v, want ErrPermissionDenied", err)
	}
}

func TestVerifyAPIKeyRejectsRevokedKey(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}
	if err := service.RevokeAPIKey(context.Background(), RevokeAPIKeyRequest{APIKeyID: created.APIKey.ID}); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}

	_, err = service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{RawKey: created.RawKey})
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("VerifyAPIKey() error = %v, want ErrInvalidCredentials", err)
	}
}

func TestVerifyAPIKeyRejectsExpiredKey(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	expiredAt := time.Date(2026, 6, 3, 15, 59, 0, 0, time.UTC)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		ExpiresAt: &expiredAt,
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("CreateAPIKey() error = %v, want ErrInvalidRequest", err)
	}
	if created.RawKey != "" {
		t.Fatal("CreateAPIKey() returned raw key for expired request")
	}
}

func TestRevokeAPIKeyRevokesStoredKey(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	if err := service.RevokeAPIKey(context.Background(), RevokeAPIKeyRequest{APIKeyID: created.APIKey.ID}); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	if store.apiKeys[created.APIKey.ID].RevokedAt == nil {
		t.Fatal("RevokeAPIKey() did not revoke key")
	}
	if store.auditCount(AuditEventAPIKeyRevoked) != 1 {
		t.Fatal("RevokeAPIKey() did not record audit event")
	}
}

func TestRevokeAPIKeySucceedsWhenAuditFails(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	store.auditErr = errors.New("audit unavailable")
	if err := service.RevokeAPIKey(context.Background(), RevokeAPIKeyRequest{APIKeyID: created.APIKey.ID}); err != nil {
		t.Fatalf("RevokeAPIKey() error = %v", err)
	}
	if store.apiKeys[created.APIKey.ID].RevokedAt == nil {
		t.Fatal("RevokeAPIKey() did not revoke key")
	}
}

func TestListAPIKeysReturnsOwnerKeys(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	for _, ownerID := range []string{"user_123", "user_123"} {
		if _, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
			OwnerType: PrincipalTypeUser,
			OwnerID:   ownerID,
		}); err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
	}
	if _, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeGroup,
		OwnerID:   "group_123",
	}); err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	keys, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("ListAPIKeys() returned %d keys, want 2", len(keys))
	}
	for _, key := range keys {
		if key.Hash != nil {
			t.Fatal("ListAPIKeys() exposed lookup hash")
		}
	}
}

func TestAPIKeyWorkflowsRequireStores(t *testing.T) {
	t.Parallel()

	service, err := New(Config{Issuer: "test-issuer"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if !errors.Is(err, ErrMissingStore) {
		t.Fatalf("CreateAPIKey() error = %v, want ErrMissingStore", err)
	}
}

func newTestService(t *testing.T) (*Service, *memoryStore) {
	t.Helper()

	now := time.Date(2026, 6, 3, 16, 0, 0, 0, time.UTC)
	store := newMemoryStore()
	store.principals[principalKey(PrincipalTypeUser, "user_123")] = Principal{
		ID:        "user_123",
		Type:      PrincipalTypeUser,
		Name:      "Test User",
		CreatedAt: now,
		UpdatedAt: now,
	}
	store.principals[principalKey(PrincipalTypeGroup, "group_123")] = Principal{
		ID:        "group_123",
		Type:      PrincipalTypeGroup,
		Name:      "Test Group",
		CreatedAt: now,
		UpdatedAt: now,
	}

	service, err := New(Config{
		Issuer:          "test-issuer",
		Clock:           fixedClock{now: now},
		Principals:      store,
		APIKeys:         store,
		APIKeyLookupKey: testLookupKey(),
		Audit:           store,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return service, store
}

func testLookupKey() []byte {
	return []byte("01234567890123456789012345678901")
}

type memoryStore struct {
	principals map[string]Principal
	apiKeys    map[string]APIKey
	byPrefix   map[string]string
	audit      []AuditEvent
	auditErr   error
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		principals: make(map[string]Principal),
		apiKeys:    make(map[string]APIKey),
		byPrefix:   make(map[string]string),
	}
}

func (s *memoryStore) GetPrincipal(_ context.Context, principalType PrincipalType, principalID string) (Principal, error) {
	principal, ok := s.principals[principalKey(principalType, principalID)]
	if !ok {
		return Principal{}, ErrNotFound
	}
	return principal, nil
}

func (s *memoryStore) CreateAPIKey(_ context.Context, key APIKey) error {
	if _, ok := s.apiKeys[key.ID]; ok {
		return ErrAlreadyExists
	}
	if _, ok := s.byPrefix[key.Prefix]; ok {
		return ErrAlreadyExists
	}
	s.apiKeys[key.ID] = key
	s.byPrefix[key.Prefix] = key.ID
	return nil
}

func (s *memoryStore) GetAPIKeyByID(_ context.Context, keyID string) (APIKey, error) {
	key, ok := s.apiKeys[keyID]
	if !ok {
		return APIKey{}, ErrNotFound
	}
	return key, nil
}

func (s *memoryStore) GetAPIKeyByPrefix(_ context.Context, prefix string) (APIKey, error) {
	keyID, ok := s.byPrefix[prefix]
	if !ok {
		return APIKey{}, ErrNotFound
	}
	return s.GetAPIKeyByID(context.Background(), keyID)
}

func (s *memoryStore) ListAPIKeys(_ context.Context, ownerType PrincipalType, ownerID string) ([]APIKey, error) {
	var keys []APIKey
	for _, key := range s.apiKeys {
		if key.OwnerType == ownerType && key.OwnerID == ownerID {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (s *memoryStore) RevokeAPIKey(_ context.Context, keyID string, revokedAt time.Time) error {
	key, ok := s.apiKeys[keyID]
	if !ok {
		return ErrNotFound
	}
	if key.RevokedAt != nil {
		return ErrInvalidState
	}
	key.RevokedAt = &revokedAt
	s.apiKeys[keyID] = key
	return nil
}

func (s *memoryStore) TouchAPIKey(_ context.Context, keyID string, usedAt time.Time) error {
	key, ok := s.apiKeys[keyID]
	if !ok {
		return ErrNotFound
	}
	key.LastUsedAt = &usedAt
	s.apiKeys[keyID] = key
	return nil
}

func (s *memoryStore) RecordAuditEvent(_ context.Context, event AuditEvent) error {
	if s.auditErr != nil {
		return s.auditErr
	}
	s.audit = append(s.audit, event)
	return nil
}

func (s *memoryStore) auditCount(eventType AuditEventType) int {
	count := 0
	for _, event := range s.audit {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func principalKey(principalType PrincipalType, principalID string) string {
	return string(principalType) + ":" + principalID
}
