package auth

import "time"

// User is the core representation of an authenticated account.
type User struct {
	ID          string
	Email       string
	DisplayName string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DisabledAt  *time.Time
}

// Session represents a server-side login session.
type Session struct {
	ID        string
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// Token represents time-bounded credential metadata.
//
// Secret token material should not be stored in this type. Storage adapters
// should persist only derived values such as hashes where appropriate.
type Token struct {
	ID        string
	FamilyID  string
	Subject   string
	Issuer    string
	Hash      []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// AuditEventType identifies a security-relevant action or state transition.
type AuditEventType string

const (
	AuditEventUserRegistered  AuditEventType = "user.registered"
	AuditEventLoginSucceeded  AuditEventType = "login.succeeded"
	AuditEventLoginFailed     AuditEventType = "login.failed"
	AuditEventLogoutSucceeded AuditEventType = "logout.succeeded"
	AuditEventTokenRefreshed  AuditEventType = "token.refreshed"
	AuditEventTokenRevoked    AuditEventType = "token.revoked"
	AuditEventPasswordChanged AuditEventType = "password.changed"
)

// AuditEvent is a structured security event.
//
// Metadata must not contain secrets, raw tokens, password hashes, credentials,
// private keys, or sensitive personal data.
type AuditEvent struct {
	ID        string
	Type      AuditEventType
	ActorID   string
	SubjectID string
	SessionID string
	TokenID   string
	Occurred  time.Time
	Metadata  map[string]string
}

// IsDisabled reports whether the user account is disabled.
func (u User) IsDisabled() bool {
	return u.DisabledAt != nil
}

// IsExpired reports whether the session has expired at now.
func (s Session) IsExpired(now time.Time) bool {
	return !s.ExpiresAt.After(now)
}

// IsRevoked reports whether the session was explicitly revoked.
func (s Session) IsRevoked() bool {
	return s.RevokedAt != nil
}

// IsExpired reports whether the token has expired at now.
func (t Token) IsExpired(now time.Time) bool {
	return !t.ExpiresAt.After(now)
}

// IsRevoked reports whether the token was explicitly revoked.
func (t Token) IsRevoked() bool {
	return t.RevokedAt != nil
}
