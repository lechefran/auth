package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lechefran/auth/token"
)

const (
	maxAPIKeyLength = 256
	maxNameLength   = 128
	maxOwnerIDLen   = 256
	maxScopes       = 64
	maxScopeLength  = 128
)

// CreateAPIKeyRequest contains metadata for a new API key.
type CreateAPIKeyRequest struct {
	OwnerType PrincipalType
	OwnerID   string
	Name      string
	Scopes    []string
	ExpiresAt *time.Time
}

// CreateAPIKeyResult returns the stored key metadata and the raw API key.
//
// RawKey is shown once. It must not be logged or stored.
type CreateAPIKeyResult struct {
	APIKey APIKey
	RawKey string
}

// VerifyAPIKeyRequest contains a raw API key and optional required scopes.
type VerifyAPIKeyRequest struct {
	RawKey         string
	RequiredScopes []string
}

// VerifyAPIKeyResult contains the verified key and owning principal.
type VerifyAPIKeyResult struct {
	APIKey    APIKey
	Principal Principal
}

// RevokeAPIKeyRequest identifies an API key to revoke.
type RevokeAPIKeyRequest struct {
	APIKeyID string
}

// ListAPIKeysRequest identifies the principal whose keys should be listed.
type ListAPIKeysRequest struct {
	OwnerType PrincipalType
	OwnerID   string
}

// CreateAPIKey creates a new API key for a user or group.
func (s *Service) CreateAPIKey(ctx context.Context, req CreateAPIKeyRequest) (CreateAPIKeyResult, error) {
	if err := validatePrincipalRef(req.OwnerType, req.OwnerID); err != nil {
		return CreateAPIKeyResult{}, err
	}
	name := strings.TrimSpace(req.Name)
	if len(name) > maxNameLength {
		return CreateAPIKeyResult{}, ErrInvalidRequest
	}
	scopes, err := normalizeScopes(req.Scopes)
	if err != nil {
		return CreateAPIKeyResult{}, err
	}
	if err := s.requireStores(s.cfg.Principals, s.cfg.APIKeys); err != nil {
		return CreateAPIKeyResult{}, err
	}

	principal, err := s.cfg.Principals.GetPrincipal(ctx, req.OwnerType, strings.TrimSpace(req.OwnerID))
	if errors.Is(err, ErrNotFound) {
		return CreateAPIKeyResult{}, ErrInvalidRequest
	}
	if err != nil {
		return CreateAPIKeyResult{}, err
	}
	if principal.IsDisabled() {
		return CreateAPIKeyResult{}, ErrDisabledPrincipal
	}

	now := s.cfg.Clock.Now()
	keyID, err := token.GeneratePublicID()
	if err != nil {
		return CreateAPIKeyResult{}, fmt.Errorf("generate api key id: %w", err)
	}
	publicID, err := token.GeneratePublicID()
	if err != nil {
		return CreateAPIKeyResult{}, fmt.Errorf("generate api key prefix: %w", err)
	}
	secret, err := token.GenerateAPIKeySecret()
	if err != nil {
		return CreateAPIKeyResult{}, fmt.Errorf("generate api key secret: %w", err)
	}

	prefix := s.cfg.KeyPrefix + "_" + publicID
	rawKey := prefix + "." + secret
	hash, err := s.lookupAPIKeyHash(rawKey)
	if err != nil {
		return CreateAPIKeyResult{}, err
	}

	expiresAt := req.ExpiresAt
	if expiresAt == nil {
		defaultExpiresAt := now.Add(s.cfg.APIKeyTTL)
		expiresAt = &defaultExpiresAt
	}
	if !expiresAt.After(now) {
		return CreateAPIKeyResult{}, ErrInvalidRequest
	}

	apiKey := APIKey{
		ID:        keyID,
		Issuer:    s.cfg.Issuer,
		Prefix:    prefix,
		Name:      name,
		OwnerType: principal.Type,
		OwnerID:   principal.ID,
		Hash:      hash,
		Scopes:    scopes,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err := s.cfg.APIKeys.CreateAPIKey(ctx, apiKey); err != nil {
		return CreateAPIKeyResult{}, err
	}
	_ = s.recordAudit(ctx, AuditEventAPIKeyCreated, "", apiKey.OwnerType, apiKey.OwnerID, apiKey.ID, nil)

	return CreateAPIKeyResult{APIKey: publicAPIKey(apiKey), RawKey: rawKey}, nil
}

// VerifyAPIKey verifies a raw API key and checks required scopes.
func (s *Service) VerifyAPIKey(ctx context.Context, req VerifyAPIKeyRequest) (VerifyAPIKeyResult, error) {
	rawKey := strings.TrimSpace(req.RawKey)
	if rawKey == "" || len(rawKey) > maxAPIKeyLength {
		return VerifyAPIKeyResult{}, ErrInvalidRequest
	}
	requiredScopes, err := normalizeScopes(req.RequiredScopes)
	if err != nil {
		return VerifyAPIKeyResult{}, ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.Principals, s.cfg.APIKeys); err != nil {
		return VerifyAPIKeyResult{}, err
	}

	prefix, err := parseAPIKeyPrefix(rawKey, s.cfg.KeyPrefix)
	if err != nil {
		_ = s.recordAudit(ctx, AuditEventAPIKeyVerificationFailed, "", "", "", "", nil)
		return VerifyAPIKeyResult{}, ErrInvalidCredentials
	}

	apiKey, err := s.cfg.APIKeys.GetAPIKeyByPrefix(ctx, prefix)
	if errors.Is(err, ErrNotFound) {
		_ = s.recordAudit(ctx, AuditEventAPIKeyVerificationFailed, "", "", "", "", map[string]string{"prefix": prefix})
		return VerifyAPIKeyResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return VerifyAPIKeyResult{}, err
	}

	hash, err := s.lookupAPIKeyHash(rawKey)
	if err != nil {
		return VerifyAPIKeyResult{}, err
	}
	if subtle.ConstantTimeCompare(hash, apiKey.Hash) != 1 {
		_ = s.recordAudit(ctx, AuditEventAPIKeyVerificationFailed, "", apiKey.OwnerType, apiKey.OwnerID, apiKey.ID, map[string]string{"prefix": prefix})
		return VerifyAPIKeyResult{}, ErrInvalidCredentials
	}

	now := s.cfg.Clock.Now()
	if apiKey.Issuer != s.cfg.Issuer || !apiKey.IsActive(now) {
		_ = s.recordAudit(ctx, AuditEventAPIKeyVerificationFailed, "", apiKey.OwnerType, apiKey.OwnerID, apiKey.ID, map[string]string{"prefix": prefix})
		return VerifyAPIKeyResult{}, ErrInvalidCredentials
	}
	if !hasRequiredScopes(apiKey.Scopes, requiredScopes) {
		return VerifyAPIKeyResult{}, ErrPermissionDenied
	}

	principal, err := s.cfg.Principals.GetPrincipal(ctx, apiKey.OwnerType, apiKey.OwnerID)
	if errors.Is(err, ErrNotFound) {
		return VerifyAPIKeyResult{}, ErrInvalidCredentials
	}
	if err != nil {
		return VerifyAPIKeyResult{}, err
	}
	if principal.IsDisabled() {
		return VerifyAPIKeyResult{}, ErrDisabledPrincipal
	}

	if err := s.cfg.APIKeys.TouchAPIKey(ctx, apiKey.ID, now); err != nil {
		return VerifyAPIKeyResult{}, err
	}
	apiKey.LastUsedAt = &now
	_ = s.recordAudit(ctx, AuditEventAPIKeyVerified, principal.ID, apiKey.OwnerType, apiKey.OwnerID, apiKey.ID, nil)

	return VerifyAPIKeyResult{APIKey: publicAPIKey(apiKey), Principal: principal}, nil
}

// RevokeAPIKey revokes an API key by ID.
func (s *Service) RevokeAPIKey(ctx context.Context, req RevokeAPIKeyRequest) error {
	keyID := strings.TrimSpace(req.APIKeyID)
	if keyID == "" {
		return ErrInvalidRequest
	}
	if err := s.requireStores(s.cfg.APIKeys); err != nil {
		return err
	}

	apiKey, err := s.cfg.APIKeys.GetAPIKeyByID(ctx, keyID)
	if err != nil {
		return err
	}

	now := s.cfg.Clock.Now()
	if err := s.cfg.APIKeys.RevokeAPIKey(ctx, keyID, now); err != nil {
		return err
	}
	_ = s.recordAudit(ctx, AuditEventAPIKeyRevoked, "", apiKey.OwnerType, apiKey.OwnerID, apiKey.ID, nil)
	return nil
}

// ListAPIKeys lists API keys for a user or group.
func (s *Service) ListAPIKeys(ctx context.Context, req ListAPIKeysRequest) ([]APIKey, error) {
	if err := validatePrincipalRef(req.OwnerType, req.OwnerID); err != nil {
		return nil, err
	}
	if err := s.requireStores(s.cfg.APIKeys); err != nil {
		return nil, err
	}
	keys, err := s.cfg.APIKeys.ListAPIKeys(ctx, req.OwnerType, strings.TrimSpace(req.OwnerID))
	if err != nil {
		return nil, err
	}
	for i := range keys {
		keys[i] = publicAPIKey(keys[i])
	}
	return keys, nil
}

func (s *Service) recordAudit(ctx context.Context, eventType AuditEventType, actorID string, principalType PrincipalType, principalID string, apiKeyID string, metadata map[string]string) error {
	if s.cfg.Audit == nil {
		return nil
	}

	eventID, err := token.GeneratePublicID()
	if err != nil {
		return fmt.Errorf("generate audit event id: %w", err)
	}
	return s.cfg.Audit.RecordAuditEvent(ctx, AuditEvent{
		ID:            eventID,
		Type:          eventType,
		ActorID:       actorID,
		PrincipalType: principalType,
		PrincipalID:   principalID,
		APIKeyID:      apiKeyID,
		Occurred:      s.cfg.Clock.Now(),
		Metadata:      metadata,
	})
}

func (s *Service) requireStores(stores ...interface{}) error {
	for _, store := range stores {
		if store == nil {
			return ErrMissingStore
		}
	}
	return nil
}

func (s *Service) lookupAPIKeyHash(rawKey string) ([]byte, error) {
	return token.HMACLookupHash(rawKey, s.apiKeyLookupKey)
}

func validatePrincipalRef(principalType PrincipalType, principalID string) error {
	principalID = strings.TrimSpace(principalID)
	if principalID == "" || len(principalID) > maxOwnerIDLen {
		return ErrInvalidRequest
	}
	switch principalType {
	case PrincipalTypeUser, PrincipalTypeGroup:
		return nil
	default:
		return ErrInvalidRequest
	}
}

func parseAPIKeyPrefix(rawKey string, keyPrefix string) (string, error) {
	prefix, secret, ok := strings.Cut(rawKey, ".")
	if !ok || prefix == "" || secret == "" {
		return "", ErrInvalidRequest
	}
	if !strings.HasPrefix(prefix, keyPrefix+"_") {
		return "", ErrInvalidRequest
	}
	publicID := strings.TrimPrefix(prefix, keyPrefix+"_")
	if !isOpaqueTokenPart(publicID) || !isOpaqueTokenPart(secret) {
		return "", ErrInvalidRequest
	}
	return prefix, nil
}

func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	if len(scopes) > maxScopes {
		return nil, ErrInvalidRequest
	}

	seen := make(map[string]struct{}, len(scopes))
	normalized := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if !isValidScope(scope) {
			return nil, ErrInvalidRequest
		}
		if _, ok := seen[scope]; ok {
			continue
		}
		seen[scope] = struct{}{}
		normalized = append(normalized, scope)
	}
	return normalized, nil
}

func hasRequiredScopes(granted []string, required []string) bool {
	if len(required) == 0 {
		return true
	}

	grantedSet := make(map[string]struct{}, len(granted))
	for _, scope := range granted {
		grantedSet[scope] = struct{}{}
	}
	for _, scope := range required {
		if _, ok := grantedSet[scope]; !ok {
			return false
		}
	}
	return true
}

func publicAPIKey(key APIKey) APIKey {
	key.Hash = nil
	key.Scopes = append([]string(nil), key.Scopes...)
	return key
}

func isValidScope(scope string) bool {
	if scope == "" || len(scope) > maxScopeLength {
		return false
	}
	for _, r := range scope {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func isKeyPrefixPart(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func isOpaqueTokenPart(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return false
		}
	}
	return true
}
