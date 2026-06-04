package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/lechefran/auth"
	"github.com/lechefran/auth/keys"
	"github.com/lechefran/auth/migrate"
	"github.com/lechefran/auth/token"
)

func main() {
	service, err := auth.New(auth.Config{
		Issuer: "auth-testbench",
	})
	if err != nil {
		log.Fatalf("create auth service: %v", err)
	}

	cfg := service.Config()
	fmt.Printf("issuer: %s\n", cfg.Issuer)
	fmt.Printf("key prefix: %s\n", cfg.KeyPrefix)
	fmt.Printf("api key ttl: %s\n", cfg.APIKeyTTL)

	secret, err := token.GenerateAPIKeySecret()
	if err != nil {
		log.Fatalf("generate api key secret: %v", err)
	}

	hmacKey, err := keys.GenerateHMACKey()
	if err != nil {
		log.Fatalf("generate hmac key: %v", err)
	}

	secretHash, err := token.HMACLookupHash(secret, hmacKey)
	if err != nil {
		log.Fatalf("hash api key secret: %v", err)
	}

	fmt.Printf("api key secret length: %d\n", len(secret))
	fmt.Printf("api key lookup hash bytes: %d\n", len(secretHash))
	fmt.Printf("hmac key bytes: %d\n", len(hmacKey))

	store := newMemoryStore()
	service, err = auth.New(auth.Config{
		Issuer:          "auth-testbench",
		Principals:      store,
		APIKeys:         store,
		APIKeyLookupKey: hmacKey,
		Audit:           store,
	})
	if err != nil {
		log.Fatalf("create api key service: %v", err)
	}

	store.principals[principalKey(auth.PrincipalTypeUser, "user_123")] = auth.Principal{
		ID:        "user_123",
		Type:      auth.PrincipalTypeUser,
		Name:      "Example User",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	created, err := service.CreateAPIKey(context.Background(), auth.CreateAPIKeyRequest{
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Name:      "testbench key",
		Scopes:    []string{"cards:read"},
	})
	if err != nil {
		log.Fatalf("create api key: %v", err)
	}

	verified, err := service.VerifyAPIKey(context.Background(), auth.VerifyAPIKeyRequest{
		RawKey:         created.RawKey,
		RequiredScopes: []string{"cards:read"},
	})
	if err != nil {
		log.Fatalf("verify api key: %v", err)
	}

	fmt.Printf("created api key prefix: %s\n", created.APIKey.Prefix)
	fmt.Printf("verified principal: %s/%s\n", verified.Principal.Type, verified.Principal.ID)

	planned := []migrate.Migration{
		{Version: 1, Name: "create_users", SQL: []string{"create table users (...)"}},
		{Version: 2, Name: "create_api_keys", SQL: []string{"create table api_keys (...)"}},
	}
	fmt.Printf("example migrations planned: %d\n", len(planned))
}

type memoryStore struct {
	principals map[string]auth.Principal
	apiKeys    map[string]auth.APIKey
	byPrefix   map[string]string
	audit      []auth.AuditEvent
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		principals: make(map[string]auth.Principal),
		apiKeys:    make(map[string]auth.APIKey),
		byPrefix:   make(map[string]string),
	}
}

func (s *memoryStore) GetPrincipal(_ context.Context, principalType auth.PrincipalType, principalID string) (auth.Principal, error) {
	principal, ok := s.principals[principalKey(principalType, principalID)]
	if !ok {
		return auth.Principal{}, auth.ErrNotFound
	}
	return principal, nil
}

func (s *memoryStore) CreateAPIKey(_ context.Context, key auth.APIKey) error {
	if _, ok := s.apiKeys[key.ID]; ok {
		return auth.ErrAlreadyExists
	}
	if _, ok := s.byPrefix[key.Prefix]; ok {
		return auth.ErrAlreadyExists
	}
	s.apiKeys[key.ID] = key
	s.byPrefix[key.Prefix] = key.ID
	return nil
}

func (s *memoryStore) GetAPIKeyByID(_ context.Context, keyID string) (auth.APIKey, error) {
	key, ok := s.apiKeys[keyID]
	if !ok {
		return auth.APIKey{}, auth.ErrNotFound
	}
	return key, nil
}

func (s *memoryStore) GetAPIKeyByPrefix(_ context.Context, prefix string) (auth.APIKey, error) {
	keyID, ok := s.byPrefix[prefix]
	if !ok {
		return auth.APIKey{}, auth.ErrNotFound
	}
	return s.GetAPIKeyByID(context.Background(), keyID)
}

func (s *memoryStore) ListAPIKeys(_ context.Context, ownerType auth.PrincipalType, ownerID string) ([]auth.APIKey, error) {
	var keys []auth.APIKey
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
		return auth.ErrNotFound
	}
	if key.RevokedAt != nil {
		return auth.ErrInvalidState
	}
	key.RevokedAt = &revokedAt
	s.apiKeys[keyID] = key
	return nil
}

func (s *memoryStore) TouchAPIKey(_ context.Context, keyID string, usedAt time.Time) error {
	key, ok := s.apiKeys[keyID]
	if !ok {
		return auth.ErrNotFound
	}
	key.LastUsedAt = &usedAt
	s.apiKeys[keyID] = key
	return nil
}

func (s *memoryStore) RecordAuditEvent(_ context.Context, event auth.AuditEvent) error {
	s.audit = append(s.audit, event)
	return nil
}

func principalKey(principalType auth.PrincipalType, principalID string) string {
	return string(principalType) + ":" + principalID
}
