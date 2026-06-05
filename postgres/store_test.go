package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	auth "github.com/lechefran/auth"
)

var (
	_ auth.PrincipalStore         = (*Store)(nil)
	_ auth.APIKeyStore            = (*Store)(nil)
	_ auth.AuditStore             = (*Store)(nil)
	_ auth.AtomicAPIKeyAuditStore = (*Store)(nil)
)

func TestStoreCursorRoundTrip(t *testing.T) {
	t.Parallel()

	want := cursorValue{
		CreatedAt: fixedPostgresTime().Format("2006-01-02T15:04:05Z07:00"),
		ID:        "key_123",
	}
	encoded, err := encodeCursor(want)
	if err != nil {
		t.Fatalf("encodeCursor() error = %v", err)
	}
	got, err := decodeCursor(encoded)
	if err != nil {
		t.Fatalf("decodeCursor() error = %v", err)
	}
	if got.CreatedAt != want.CreatedAt || got.ID != want.ID {
		t.Fatalf("decodeCursor() = %+v, want %+v", got, want)
	}
}

func TestStoreCursorRejectsInvalidValues(t *testing.T) {
	t.Parallel()

	for _, cursor := range []string{
		"not-base64",
		"e30",
		strings.Repeat("a", maxStoreCursorLength+1),
	} {
		if _, err := decodeCursor(cursor); !errors.Is(err, auth.ErrInvalidRequest) {
			t.Fatalf("decodeCursor(%q) error = %v, want ErrInvalidRequest", cursor, err)
		}
	}
}

func TestNormalizeStorePage(t *testing.T) {
	t.Parallel()

	page, err := normalizeStorePage(auth.PageRequest{})
	if err != nil {
		t.Fatalf("normalizeStorePage() error = %v", err)
	}
	if page.Limit != auth.DefaultPageLimit {
		t.Fatalf("default limit = %d, want %d", page.Limit, auth.DefaultPageLimit)
	}

	page, err = normalizeStorePage(auth.PageRequest{Limit: auth.MaxPageLimit + 1})
	if err != nil {
		t.Fatalf("normalizeStorePage(max) error = %v", err)
	}
	if page.Limit != auth.MaxPageLimit {
		t.Fatalf("max limit = %d, want %d", page.Limit, auth.MaxPageLimit)
	}

	if _, err := normalizeStorePage(auth.PageRequest{Limit: -1}); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("normalizeStorePage(negative) error = %v, want ErrInvalidRequest", err)
	}
}

func TestEncodeDecodeScopes(t *testing.T) {
	t.Parallel()

	encoded, err := encodeScopes([]string{"cards:read", "cards:write"})
	if err != nil {
		t.Fatalf("encodeScopes() error = %v", err)
	}
	got, err := decodeScopes([]byte(encoded))
	if err != nil {
		t.Fatalf("decodeScopes() error = %v", err)
	}
	if len(got) != 2 || got[0] != "cards:read" || got[1] != "cards:write" {
		t.Fatalf("decodeScopes() = %v", got)
	}
}

func TestMapWriteErrorUsesPostgresSQLState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		code string
		want error
	}{
		{name: "foreign key", code: "23503", want: auth.ErrNotFound},
		{name: "unique", code: "23505", want: auth.ErrAlreadyExists},
		{name: "check", code: "23514", want: auth.ErrInvalidState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := mapWriteError(&pgconn.PgError{Code: tt.code})
			if !errors.Is(err, tt.want) {
				t.Fatalf("mapWriteError(%s) = %v, want %v", tt.code, err, tt.want)
			}
		})
	}
}

func fixedPostgresTime() time.Time {
	return time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
}
