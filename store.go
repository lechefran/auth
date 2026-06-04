package auth

import (
	"context"
	"time"
)

// UserStore persists account records.
type UserStore interface {
	CreateUser(ctx context.Context, user User) error
	GetUserByID(ctx context.Context, userID string) (User, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)
	UpdateUser(ctx context.Context, user User) error
}

// CredentialStore persists credential verifiers.
//
// Implementations must never log passwordHash values. Password hashes are not
// plaintext secrets, but they are still sensitive verifier material.
type CredentialStore interface {
	SetPasswordHash(ctx context.Context, userID string, passwordHash []byte) error
	GetPasswordHash(ctx context.Context, userID string) ([]byte, error)
	DeletePasswordHash(ctx context.Context, userID string) error
}

// SessionStore persists server-side session state.
type SessionStore interface {
	CreateSession(ctx context.Context, session Session) error
	GetSessionByID(ctx context.Context, sessionID string) (Session, error)
	ListSessionsByUserID(ctx context.Context, userID string) ([]Session, error)
	RevokeSession(ctx context.Context, sessionID string, revokedAt time.Time) error
	RevokeUserSessions(ctx context.Context, userID string, revokedAt time.Time) error
}

// TokenStore persists token metadata and hashed token lookups.
//
// Raw token values must never be persisted. Store adapters should index only
// token hashes produced by the token generation module.
type TokenStore interface {
	CreateToken(ctx context.Context, token Token) error
	GetTokenByID(ctx context.Context, tokenID string) (Token, error)
	GetTokenByHash(ctx context.Context, tokenHash []byte) (Token, error)
	RevokeToken(ctx context.Context, tokenID string, revokedAt time.Time) error
	RevokeTokenFamily(ctx context.Context, familyID string, revokedAt time.Time) error
}

// AuditStore records security-relevant events.
type AuditStore interface {
	RecordAuditEvent(ctx context.Context, event AuditEvent) error
}
