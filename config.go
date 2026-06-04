package auth

import (
	"errors"
	"time"
)

var (
	// ErrInvalidConfig is returned when a service configuration is unsafe or
	// incomplete.
	ErrInvalidConfig = errors.New("auth: invalid config")
)

const (
	defaultAPIKeyTTL = 90 * 24 * time.Hour
	defaultKeyPrefix = "ak"
)

// Config controls the core authentication service.
type Config struct {
	// Issuer identifies this auth service in generated credentials and audit
	// records. It must be stable within a deployment.
	Issuer string

	// Clock supplies time for token and session lifecycles. The system clock is
	// used when this is nil.
	Clock Clock

	// KeyPrefix is the public prefix used in generated API keys. It must not
	// contain whitespace, underscores, or periods.
	KeyPrefix string

	// APIKeyTTL is the default lifetime for generated API keys when callers do
	// not provide an explicit expiration.
	APIKeyTTL time.Duration

	// Principals stores users and groups that can own API keys.
	Principals PrincipalStore

	// APIKeys stores API key metadata and lookup hashes.
	APIKeys APIKeyStore

	// Audit records security-relevant events. Workflows should remain usable
	// without audit storage only when callers explicitly choose that tradeoff.
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
	if containsKeyDelimiter(cfg.KeyPrefix) {
		return errors.Join(ErrInvalidConfig, errors.New("key prefix contains a reserved delimiter"))
	}
	if cfg.APIKeyTTL <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("api key ttl must be positive"))
	}
	return nil
}

func containsKeyDelimiter(value string) bool {
	for _, r := range value {
		if r == '_' || r == '.' || r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return true
		}
	}
	return false
}
