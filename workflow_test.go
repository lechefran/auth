package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
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

func TestCreateAPIKeyRollsBackWhenAtomicAuditFails(t *testing.T) {
	t.Parallel()

	service, store := newAtomicTestService(t)
	store.auditErr = errors.New("audit unavailable")

	_, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err == nil {
		t.Fatal("CreateAPIKey() returned nil error")
	}
	if len(store.apiKeys) != 0 {
		t.Fatalf("stored keys = %d, want 0", len(store.apiKeys))
	}
	if store.atomicCreates != 1 {
		t.Fatalf("atomic creates = %d, want 1", store.atomicCreates)
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

func TestVerifyAPIKeyAuditsInvalidRawKey(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	_, err := service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{
		RawKey: strings.Repeat("x", maxAPIKeyLength+1),
	})
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("VerifyAPIKey() error = %v, want ErrInvalidRequest", err)
	}
	if store.auditCount(AuditEventAPIKeyVerificationFailed) != 1 {
		t.Fatal("VerifyAPIKey() did not audit oversized raw key")
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

func TestVerifyAPIKeySucceedsWhenTouchFails(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	store.touchErr = errors.New("last-used write unavailable")
	verified, err := service.VerifyAPIKey(context.Background(), VerifyAPIKeyRequest{RawKey: created.RawKey})
	if err != nil {
		t.Fatalf("VerifyAPIKey() error = %v", err)
	}
	if verified.APIKey.ID != created.APIKey.ID {
		t.Fatalf("VerifyAPIKey() ID = %q, want %q", verified.APIKey.ID, created.APIKey.ID)
	}
	if verified.APIKey.LastUsedAt != nil {
		t.Fatal("VerifyAPIKey() returned LastUsedAt after touch failure")
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

func TestRevokeAPIKeyRollsBackWhenAtomicAuditFails(t *testing.T) {
	t.Parallel()

	service, store := newAtomicTestService(t)
	created, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("CreateAPIKey() error = %v", err)
	}

	store.auditErr = errors.New("audit unavailable")
	err = service.RevokeAPIKey(context.Background(), RevokeAPIKeyRequest{APIKeyID: created.APIKey.ID})
	if err == nil {
		t.Fatal("RevokeAPIKey() returned nil error")
	}
	if store.apiKeys[created.APIKey.ID].RevokedAt != nil {
		t.Fatal("RevokeAPIKey() revoked key after atomic audit failure")
	}
	if store.atomicRevokes != 1 {
		t.Fatalf("atomic revokes = %d, want 1", store.atomicRevokes)
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

	page, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	})
	if err != nil {
		t.Fatalf("ListAPIKeys() error = %v", err)
	}
	if len(page.Items) != 2 {
		t.Fatalf("ListAPIKeys() returned %d keys, want 2", len(page.Items))
	}
	for _, key := range page.Items {
		if key.Hash != nil {
			t.Fatal("ListAPIKeys() exposed lookup hash")
		}
	}
}

func TestListAPIKeysPaginatesWithLimitAndCursor(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)
	for i := 0; i < 5; i++ {
		if _, err := service.CreateAPIKey(context.Background(), CreateAPIKeyRequest{
			OwnerType: PrincipalTypeUser,
			OwnerID:   "user_123",
			Name:      fmt.Sprintf("key-%d", i),
		}); err != nil {
			t.Fatalf("CreateAPIKey() error = %v", err)
		}
	}

	first, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Page:      PageRequest{Limit: 2},
	})
	if err != nil {
		t.Fatalf("ListAPIKeys(first) error = %v", err)
	}
	if len(first.Items) != 2 {
		t.Fatalf("first page length = %d, want 2", len(first.Items))
	}
	if !first.HasMore() {
		t.Fatal("first page HasMore() = false, want true")
	}

	second, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Page:      PageRequest{Limit: 2, Cursor: first.NextCursor},
	})
	if err != nil {
		t.Fatalf("ListAPIKeys(second) error = %v", err)
	}
	if len(second.Items) != 2 {
		t.Fatalf("second page length = %d, want 2", len(second.Items))
	}
	if !second.HasMore() {
		t.Fatal("second page HasMore() = false, want true")
	}

	third, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Page:      PageRequest{Limit: 2, Cursor: second.NextCursor},
	})
	if err != nil {
		t.Fatalf("ListAPIKeys(third) error = %v", err)
	}
	if len(third.Items) != 1 {
		t.Fatalf("third page length = %d, want 1", len(third.Items))
	}
	if third.HasMore() {
		t.Fatal("third page HasMore() = true, want false")
	}
}

func TestListAPIKeysAppliesDefaultAndMaxLimit(t *testing.T) {
	t.Parallel()

	service, store := newTestService(t)
	if _, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
	}); err != nil {
		t.Fatalf("ListAPIKeys(default) error = %v", err)
	}
	if store.lastPage.Limit != DefaultPageLimit {
		t.Fatalf("default limit = %d, want %d", store.lastPage.Limit, DefaultPageLimit)
	}

	if _, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
		OwnerType: PrincipalTypeUser,
		OwnerID:   "user_123",
		Page:      PageRequest{Limit: MaxPageLimit + 1},
	}); err != nil {
		t.Fatalf("ListAPIKeys(max) error = %v", err)
	}
	if store.lastPage.Limit != MaxPageLimit {
		t.Fatalf("max limit = %d, want %d", store.lastPage.Limit, MaxPageLimit)
	}
}

func TestListAPIKeysRejectsInvalidPageRequest(t *testing.T) {
	t.Parallel()

	service, _ := newTestService(t)

	tests := []PageRequest{
		{Limit: -1},
		{Cursor: "bad cursor"},
	}
	for _, pageReq := range tests {
		_, err := service.ListAPIKeys(context.Background(), ListAPIKeysRequest{
			OwnerType: PrincipalTypeUser,
			OwnerID:   "user_123",
			Page:      pageReq,
		})
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("ListAPIKeys(%+v) error = %v, want ErrInvalidRequest", pageReq, err)
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

func newAtomicTestService(t *testing.T) (*Service, *atomicMemoryStore) {
	t.Helper()

	service, store := newTestService(t)
	atomicStore := &atomicMemoryStore{memoryStore: store}
	service.cfg.APIKeys = atomicStore
	service.cfg.Audit = atomicStore
	return service, atomicStore
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
	touchErr   error
	lastPage   PageRequest
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

func (s *memoryStore) ListAPIKeys(_ context.Context, ownerType PrincipalType, ownerID string, page PageRequest) (Page[APIKey], error) {
	s.lastPage = page
	var keys []APIKey
	for _, key := range s.apiKeys {
		if key.OwnerType == ownerType && key.OwnerID == ownerID {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].CreatedAt.Equal(keys[j].CreatedAt) {
			return keys[i].ID < keys[j].ID
		}
		return keys[i].CreatedAt.Before(keys[j].CreatedAt)
	})

	start := 0
	if page.Cursor != "" {
		parsed, err := strconv.Atoi(page.Cursor)
		if err != nil || parsed < 0 || parsed > len(keys) {
			return Page[APIKey]{}, ErrInvalidRequest
		}
		start = parsed
	}

	end := start + page.Limit
	if end > len(keys) {
		end = len(keys)
	}
	result := Page[APIKey]{
		Items: append([]APIKey(nil), keys[start:end]...),
	}
	if end < len(keys) {
		result.NextCursor = strconv.Itoa(end)
	}
	return result, nil
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
	if s.touchErr != nil {
		return s.touchErr
	}
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

type atomicMemoryStore struct {
	*memoryStore
	atomicCreates int
	atomicRevokes int
}

func (s *atomicMemoryStore) CreateAPIKeyWithAudit(ctx context.Context, key APIKey, event AuditEvent) error {
	s.atomicCreates++
	if err := s.CreateAPIKey(ctx, key); err != nil {
		return err
	}
	if err := s.RecordAuditEvent(ctx, event); err != nil {
		delete(s.byPrefix, key.Prefix)
		delete(s.apiKeys, key.ID)
		return err
	}
	return nil
}

func (s *atomicMemoryStore) RevokeAPIKeyWithAudit(ctx context.Context, keyID string, revokedAt time.Time, event AuditEvent) error {
	s.atomicRevokes++
	previous, ok := s.apiKeys[keyID]
	if !ok {
		return ErrNotFound
	}
	if err := s.RevokeAPIKey(ctx, keyID, revokedAt); err != nil {
		return err
	}
	if err := s.RecordAuditEvent(ctx, event); err != nil {
		s.apiKeys[keyID] = previous
		return err
	}
	return nil
}

func principalKey(principalType PrincipalType, principalID string) string {
	return string(principalType) + ":" + principalID
}
