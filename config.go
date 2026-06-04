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
	defaultAccessTokenTTL  = 15 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour
	defaultSessionTTL      = 24 * time.Hour
)

// Config controls the core authentication service.
type Config struct {
	// Issuer identifies this auth service in generated credentials and audit
	// records. It must be stable within a deployment.
	Issuer string

	// Clock supplies time for token and session lifecycles. The system clock is
	// used when this is nil.
	Clock Clock

	// AccessTokenTTL is the lifetime for short-lived access tokens.
	AccessTokenTTL time.Duration

	// RefreshTokenTTL is the maximum lifetime for refresh tokens.
	RefreshTokenTTL time.Duration

	// SessionTTL is the maximum lifetime for user sessions.
	SessionTTL time.Duration

	// Users stores account records.
	Users UserStore

	// Credentials stores password hashes and other credential verifiers.
	Credentials CredentialStore

	// Sessions stores server-side login sessions.
	Sessions SessionStore

	// Tokens stores time-bounded token metadata and hashed token lookups.
	Tokens TokenStore

	// Audit records security-relevant events. Workflows should remain usable
	// without audit storage only when callers explicitly choose that tradeoff.
	Audit AuditStore
}

func normalizeConfig(cfg Config) Config {
	if cfg.Clock == nil {
		cfg.Clock = systemClock{}
	}
	if cfg.AccessTokenTTL == 0 {
		cfg.AccessTokenTTL = defaultAccessTokenTTL
	}
	if cfg.RefreshTokenTTL == 0 {
		cfg.RefreshTokenTTL = defaultRefreshTokenTTL
	}
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = defaultSessionTTL
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
	if cfg.AccessTokenTTL <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("access token ttl must be positive"))
	}
	if cfg.RefreshTokenTTL <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("refresh token ttl must be positive"))
	}
	if cfg.SessionTTL <= 0 {
		return errors.Join(ErrInvalidConfig, errors.New("session ttl must be positive"))
	}
	if cfg.AccessTokenTTL >= cfg.RefreshTokenTTL {
		return errors.Join(ErrInvalidConfig, errors.New("access token ttl must be shorter than refresh token ttl"))
	}
	if cfg.SessionTTL > cfg.RefreshTokenTTL {
		return errors.Join(ErrInvalidConfig, errors.New("session ttl must not exceed refresh token ttl"))
	}
	return nil
}
