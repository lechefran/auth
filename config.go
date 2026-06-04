package auth

import (
	"errors"
	"time"

	"github.com/lechefran/auth/token"
)

var (
	// ErrInvalidConfig is returned when a service configuration is unsafe or
	// incomplete.
	ErrInvalidConfig = errors.New("auth: invalid config")
)

const (
	defaultAPIKeyTTL = 90 * 24 * time.Hour
	defaultKeyPrefix = "ak"
	maxKeyPrefixLen  = 32
)

// Config controls the core authentication service.
type Config struct {
	// Issuer identifies this auth service in generated credentials and audit
	// records. It must be stable within a deployment.
	Issuer string

	// Clock supplies time for token and session lifecycles. The system clock is
	// used when this is nil.
	Clock Clock

	// KeyPrefix is the public prefix used in generated API keys. It may contain
	// ASCII letters, digits, and hyphens.
	KeyPrefix string

	// APIKeyTTL is the default lifetime for generated API keys when callers do
	// not provide an explicit expiration.
	APIKeyTTL time.Duration

	// APIKeyLookupKey is the application-controlled HMAC key used to hash API
	// keys before storage. It is required when APIKeys is configured and must
	// come from secret management, not source code.
	APIKeyLookupKey []byte

	// Principals stores users and groups that can own API keys.
	Principals PrincipalStore

	// APIKeys stores API key metadata and lookup hashes.
	APIKeys APIKeyStore

	// Audit records security-relevant events. Audit writes and last-used updates
	// are best-effort for completed workflows so metadata storage failures do
	// not orphan newly created API keys or deny otherwise valid keys.
	Audit AuditStore
}

func normalizeConfig(cfg Config) Config {
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = defaultKeyPrefix
	}
	if cfg.APIKeyTTL == 0 {
		cfg.APIKeyTTL = defaultAPIKeyTTL
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if cfg.Issuer == "" {
		return errors.Join(ErrInvalidConfig, errors.New("issuer is required"))
	}
	if cfg.Clock == nil {
		return errors.Join(ErrInvalidConfig, errors.New("clock is required"))
	}
	if cfg.KeyPrefix == "" {
		return errors.Join(ErrInvalidConfig, errors.New("key prefix is required"))
	}
	if len(cfg.KeyPrefix) > maxKeyPrefixLen {
		return errors.Join(ErrInvalidConfig, errors.New("key prefix is too long"))
	}
	if !isKeyPrefixPart(cfg.KeyPrefix) {
		return errors.Join(ErrInvalidConfig, errors.New("key prefix contains invalid characters"))
	}
	if cfg.APIKeyTTL <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("api key ttl must be positive"))
	}
	if cfg.APIKeys != nil && len(cfg.APIKeyLookupKey) < token.MinLookupKeyBytes {
		return errors.Join(ErrInvalidConfig, token.ErrWeakLookupKey)
	}
	return nil
}
