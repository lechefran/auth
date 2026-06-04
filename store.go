package auth

import (
	"context"
	"time"
)

// UserStore persists account records.
type UserStore interface {
	// CreateUser stores a new user. It returns ErrAlreadyExists when a unique
	// user field, such as ID or email, is already present.
	CreateUser(ctx context.Context, user User) error

	// GetUserByID returns ErrNotFound when userID does not exist.
	GetUserByID(ctx context.Context, userID string) (User, error)

	// GetUserByEmail returns ErrNotFound when email does not exist.
	GetUserByEmail(ctx context.Context, email string) (User, error)

	// UpdateUser returns ErrNotFound when the user does not exist and
	// ErrConflict when a unique field collides with another user.
	UpdateUser(ctx context.Context, user User) error
}

// CredentialStore persists credential verifiers.
//
// Implementations must never log passwordHash values. Password hashes are not
// plaintext secrets, but they are still sensitive verifier material.
type CredentialStore interface {
	// SetPasswordHash creates or replaces a user's password verifier. It
	// returns ErrNotFound when userID does not exist.
	SetPasswordHash(ctx context.Context, userID string, passwordHash []byte) error

	// GetPasswordHash returns ErrNotFound when no password verifier exists.
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)

	// DeletePasswordHash returns ErrNotFound when no password verifier exists.
	DeletePasswordHash(ctx context.Context, userID string) error
}

// SessionStore persists server-side session state.
type SessionStore interface {
	// CreateSession stores a new session. It returns ErrAlreadyExists when the
	// session ID is already present.
	CreateSession(ctx context.Context, session Session) error

	// GetSessionByID returns ErrNotFound when sessionID does not exist.
	GetSessionByID(ctx context.Context, sessionID string) (Session, error)

	// ListSessionsByUserID returns an empty slice when the user has no sessions.
	ListSessionsByUserID(ctx context.Context, userID string) ([]Session, error)

	// RevokeSession returns ErrNotFound when sessionID does not exist and
	// ErrInvalidState when the session cannot be revoked.
	RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error

	// RevokeUserSessions revokes all active sessions for the user. It should be
	// idempotent and return nil when the user has no active sessions.
	RevokeUserSessions(ctx context.Context, userID string, revokedAt time.Time) error
}

// TokenStore persists token metadata and hashed token lookups.
//
// Raw token values must never be persisted. Store adapters should index only
// token hashes produced by the token generation module.
type TokenStore interface {
	// CreateToken stores token metadata. It returns ErrAlreadyExists when the
	// token ID or token hash is already present.
	CreateToken(ctx context.Context, token Token) error

	// GetTokenByID returns ErrNotFound when tokenID does not exist.
	GetTokenByID(ctx context.Context, tokenID string) (Token, error)

	// GetTokenByHash returns ErrNotFound when tokenHash does not exist.
	GetTokenByHash(ctx context.Context, tokenHash []byte) (Token, error)

	// RevokeToken returns ErrNotFound when tokenID does not exist and
	// ErrInvalidState when the token cannot be revoked.
	RevokeToken(ctx context.Context, tokenID string, revokedAt time.Time) error

	// RevokeTokenFamily revokes every token in a token family. It should be
	// idempotent and return nil when the family has no active tokens.
	RevokeTokenFamily(ctx context.Context, familyID string, revokedAt time.Time) error
}

// AuditStore records security-relevant events.
type AuditStore interface {
	// RecordAuditEvent stores an audit event. It returns ErrAlreadyExists when
	// the event ID is already present.
	RecordAuditEvent(ctx context.Context, event AuditEvent) error
}
