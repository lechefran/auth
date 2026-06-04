package auth

import (
	"context"
	"time"
)

// PrincipalStore persists users and groups that can own API keys.
type PrincipalStore interface {
	// GetPrincipal returns ErrNotFound when the principal does not exist.
	GetPrincipal(ctx context.Context, principalType PrincipalType, principalID string) (Principal, error)
}

// APIKeyStore persists API key metadata and hashed key lookups.
//
// Raw API key values must never be persisted. Store adapters should index by
// Prefix and store only Hash for verification.
type APIKeyStore interface {
	// CreateAPIKey stores key metadata. It returns ErrAlreadyExists when the key
	// ID or prefix is already present.
	CreateAPIKey(ctx context.Context, key APIKey) error

	// GetAPIKeyByID returns ErrNotFound when keyID does not exist.
	GetAPIKeyByID(ctx context.Context, keyID string) (APIKey, error)

	// GetAPIKeyByPrefix returns ErrNotFound when prefix does not exist.
	GetAPIKeyByPrefix(ctx context.Context, prefix string) (APIKey, error)

	// ListAPIKeys returns keys for a principal in a stable deterministic order.
	// It returns an empty page when the principal has no keys. Cursor values are
	// opaque and store-defined.
	ListAPIKeys(ctx context.Context, ownerType PrincipalType, ownerID string, page PageRequest) (Page[APIKey], error)

	// RevokeAPIKey returns ErrNotFound when keyID does not exist and
	// ErrInvalidState when the key cannot be revoked.
	RevokeAPIKey(ctx context.Context, keyID string, revokedAt time.Time) error

	// TouchAPIKey records successful use. The core service treats this as
	// best-effort metadata and does not fail verification when it returns an
	// error.
	TouchAPIKey(ctx context.Context, keyID string, usedAt time.Time) error
}

// AuditStore records security-relevant events.
type AuditStore interface {
	// RecordAuditEvent stores an audit event. It returns ErrAlreadyExists when
	// the event ID is already present.
	RecordAuditEvent(ctx context.Context, event AuditEvent) error
}

// AtomicAPIKeyAuditStore optionally persists API key mutations and their audit
// event in one store-owned atomic operation.
//
// Store adapters that can provide transactions should implement this interface
// when their APIKeyStore and AuditStore data live in the same database.
type AtomicAPIKeyAuditStore interface {
	// CreateAPIKeyWithAudit stores key metadata and its creation audit event in
	// one atomic operation.
	CreateAPIKeyWithAudit(ctx context.Context, key APIKey, event AuditEvent) error

	// RevokeAPIKeyWithAudit reads and revokes an API key, stores its revocation
	// audit event, and returns the revoked key metadata in one atomic operation.
	//
	// Implementations should populate event API key and principal fields from
	// the key read inside the atomic operation.
	RevokeAPIKeyWithAudit(ctx context.Context, keyID string, revokedAt time.Time, event AuditEvent) (APIKey, error)
}
