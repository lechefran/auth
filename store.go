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

	// ListAPIKeys returns keys for a principal. It returns an empty slice when
	// the principal has no keys.
	ListAPIKeys(ctx context.Context, ownerType PrincipalType, ownerID string) ([]APIKey, error)

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
