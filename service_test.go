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
	if cfg.AccessTokenTTL != defaultAccessTokenTTL {
		t.Fatalf("AccessTokenTTL = %v, want %v", cfg.AccessTokenTTL, defaultAccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != defaultRefreshTokenTTL {
		t.Fatalf("RefreshTokenTTL = %v, want %v", cfg.RefreshTokenTTL, defaultRefreshTokenTTL)
	}
	if cfg.SessionTTL != defaultSessionTTL {
		t.Fatalf("SessionTTL = %v, want %v", cfg.SessionTTL, defaultSessionTTL)
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
			name: "negative access token ttl",
			cfg: Config{
				Issuer:         "test-issuer",
				AccessTokenTTL: -time.Second,
			},
		},
		{
			name: "negative refresh token ttl",
			cfg: Config{
				Issuer:          "test-issuer",
				RefreshTokenTTL: -time.Second,
			},
		},
		{
			name: "negative session ttl",
			cfg: Config{
				Issuer:     "test-issuer",
				SessionTTL: -time.Second,
			},
		},
		{
			name: "access token ttl exceeds refresh token ttl",
			cfg: Config{
				Issuer:          "test-issuer",
				AccessTokenTTL:  time.Hour,
				RefreshTokenTTL: time.Minute,
			},
		},
		{
			name: "session ttl exceeds refresh token ttl",
			cfg: Config{
				Issuer:          "test-issuer",
				RefreshTokenTTL: time.Hour,
				SessionTTL:      2 * time.Hour,
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
