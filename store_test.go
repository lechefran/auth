package auth

import (
	"context"
	"time"
)

type compilePrincipalStore struct{}

func (compilePrincipalStore) GetPrincipal(context.Context, PrincipalType, string) (Principal, error) {
	return Principal{}, nil
}

type compileAPIKeyStore struct{}

func (compileAPIKeyStore) CreateAPIKey(context.Context, APIKey) error {
	return nil
}

func (compileAPIKeyStore) GetAPIKeyByID(context.Context, string) (APIKey, error) {
	return APIKey{}, nil
}

func (compileAPIKeyStore) GetAPIKeyByPrefix(context.Context, string) (APIKey, error) {
	return APIKey{}, nil
}

func (compileAPIKeyStore) ListAPIKeys(context.Context, PrincipalType, string) ([]APIKey, error) {
	return nil, nil
}

func (compileAPIKeyStore) RevokeAPIKey(context.Context, string, time.Time) error {
	return nil
}

func (compileAPIKeyStore) TouchAPIKey(context.Context, string, time.Time) error {
	return nil
}

type compileAuditStore struct{}

func (compileAuditStore) RecordAuditEvent(context.Context, AuditEvent) error {
	return nil
}

var (
	_ PrincipalStore = compilePrincipalStore{}
	_ APIKeyStore    = compileAPIKeyStore{}
	_ AuditStore     = compileAuditStore{}
)
