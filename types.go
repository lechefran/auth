package auth

import "time"

// PrincipalType identifies the kind of entity that can own an API key.
type PrincipalType string

const (
	PrincipalTypeUser  PrincipalType = "user"
	PrincipalTypeGroup PrincipalType = "group"
)

// Principal is a user or group that can own API keys.
type Principal struct {
	ID         string
	Type       PrincipalType
	Name       string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	DisabledAt *time.Time
}

// APIKey represents stored API key metadata.
//
// Raw key material must never be stored in this type. Store adapters persist
// Hash for lookup verification and Prefix for efficient key lookup.
type APIKey struct {
	ID         string
	Issuer     string
	Prefix     string
	Name       string
	OwnerType  PrincipalType
	OwnerID    string
	Hash       []byte
	Scopes     []string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	RevokedAt  *time.Time
	LastUsedAt *time.Time
}

// AuditEventType identifies a security-relevant action or state transition.
type AuditEventType string

const (
	AuditEventAPIKeyCreated            AuditEventType = "api_key.created"
	AuditEventAPIKeyVerified           AuditEventType = "api_key.verified"
	AuditEventAPIKeyVerificationFailed AuditEventType = "api_key.verification_failed"
	AuditEventAPIKeyRevoked            AuditEventType = "api_key.revoked"
)

// AuditEvent is a structured security event.
//
// Metadata must not contain secrets, raw API keys, key hashes, private keys, or
// sensitive personal data.
type AuditEvent struct {
	ID            string
	Type          AuditEventType
	ActorID       string
	PrincipalType PrincipalType
	PrincipalID   string
	APIKeyID      string
	Occurred      time.Time
	Metadata      map[string]string
}

// IsDisabled reports whether the principal is disabled.
func (p Principal) IsDisabled() bool {
	return p.DisabledAt != nil
}

// IsExpired reports whether the API key has expired at now.
func (k APIKey) IsExpired(now time.Time) bool {
	return k.ExpiresAt != nil && !k.ExpiresAt.After(now)
}

// IsRevoked reports whether the API key was explicitly revoked.
func (k APIKey) IsRevoked() bool {
	return k.RevokedAt != nil
}

// IsActive reports whether the API key is neither expired nor revoked.
func (k APIKey) IsActive(now time.Time) bool {
	return !k.IsExpired(now) && !k.IsRevoked()
}
