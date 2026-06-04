package auth

import (
	"errors"
	"testing"
	"time"
)

type fixedClock struct {
	now time.Time
}

func (c fixedClock) Now() time.Time {
	return c.now
}

func TestNewAppliesSecureDefaults(t *testing.T) {
	t.Parallel()

	service, err := New(Config{Issuer: "test-issuer"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cfg := service.Config()
	if cfg.Clock == nil {
		t.Fatal("expected default clock")
	}
	if cfg.KeyPrefix != defaultKeyPrefix {
		t.Fatalf("KeyPrefix = %q, want %q", cfg.KeyPrefix, defaultKeyPrefix)
	}
	if cfg.APIKeyTTL != defaultAPIKeyTTL {
		t.Fatalf("APIKeyTTL = %v, want %v", cfg.APIKeyTTL, defaultAPIKeyTTL)
	}
}

func TestNewKeepsAPIKeyLookupKeyPrivate(t *testing.T) {
	t.Parallel()

	store := newMemoryStore()
	lookupKey := testLookupKey()
	service, err := New(Config{
		Issuer:          "test-issuer",
		Principals:      store,
		APIKeys:         store,
		APIKeyLookupKey: lookupKey,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	lookupKey[0] ^= 0xff

	if service.apiKeyLookupKey[0] == lookupKey[0] {
		t.Fatal("New() retained caller-owned api key lookup key slice")
	}
	if service.Config().APIKeyLookupKey != nil {
		t.Fatal("Config() exposed api key lookup key")
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "missing issuer",
			cfg:  Config{},
		},
		{
			name: "reserved key prefix delimiter",
			cfg: Config{
				Issuer:    "test-issuer",
				KeyPrefix: "bad_prefix",
			},
		},
		{
			name: "negative api key ttl",
			cfg: Config{
				Issuer:    "test-issuer",
				APIKeyTTL: -time.Second,
			},
		},
		{
			name: "api key store without lookup key",
			cfg: Config{
				Issuer:  "test-issuer",
				APIKeys: compileAPIKeyStore{},
			},
		},
		{
			name: "weak lookup key",
			cfg: Config{
				Issuer:          "test-issuer",
				APIKeys:         compileAPIKeyStore{},
				APIKeyLookupKey: []byte("short"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := New(tt.cfg)
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestNewPreservesExplicitClock(t *testing.T) {
	t.Parallel()

	want := fixedClock{now: time.Date(2026, 6, 3, 16, 0, 0, 0, time.UTC)}
	service, err := New(Config{
		Issuer: "test-issuer",
		Clock:  want,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if got := service.Config().Clock.Now(); !got.Equal(want.now) {
		t.Fatalf("Clock.Now() = %v, want %v", got, want.now)
	}
}
