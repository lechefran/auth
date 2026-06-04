package auth

import (
	"context"
	"time"
)

type compileUserStore struct{}

func (compileUserStore) CreateUser(context.Context, User) error {
	return nil
}

func (compileUserStore) GetUserByID(context.Context, string) (User, error) {
	return User{}, nil
}

func (compileUserStore) GetUserByEmail(context.Context, string) (User, error) {
	return User{}, nil
}

func (compileUserStore) UpdateUser(context.Context, User) error {
	return nil
}

type compileCredentialStore struct{}

func (compileCredentialStore) SetPasswordHash(context.Context, string, []byte) error {
	return nil
}

func (compileCredentialStore) GetPasswordHash(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (compileCredentialStore) DeletePasswordHash(context.Context, string) error {
	return nil
}

type compileSessionStore struct{}

func (compileSessionStore) CreateSession(context.Context, Session) error {
	return nil
}

func (compileSessionStore) GetSessionByID(context.Context, string) (Session, error) {
	return Session{}, nil
}

func (compileSessionStore) ListSessionsByUserID(context.Context, string) ([]Session, error) {
	return nil, nil
}

func (compileSessionStore) RevokeSession(context.Context, string, time.Time) error {
	return nil
}

func (compileSessionStore) RevokeUserSessions(context.Context, string, time.Time) error {
	return nil
}

type compileTokenStore struct{}

func (compileTokenStore) CreateToken(context.Context, Token) error {
	return nil
}

func (compileTokenStore) GetTokenByID(context.Context, string) (Token, error) {
	return Token{}, nil
}

func (compileTokenStore) GetTokenByHash(context.Context, []byte) (Token, error) {
	return Token{}, nil
}

func (compileTokenStore) RevokeToken(context.Context, string, time.Time) error {
	return nil
}

func (compileTokenStore) RevokeTokenFamily(context.Context, string, time.Time) error {
	return nil
}

type compileAuditStore struct{}

func (compileAuditStore) RecordAuditEvent(context.Context, AuditEvent) error {
	return nil
}

var (
	_ UserStore       = compileUserStore{}
	_ CredentialStore = compileCredentialStore{}
	_ SessionStore    = compileSessionStore{}
	_ TokenStore      = compileTokenStore{}
	_ AuditStore      = compileAuditStore{}
)
