package mysql

import (
	"errors"
	"strings"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
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
		CreatedAt: fixedMySQLTime().Format(time.RFC3339Nano),
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
	for _, value := range []any{[]byte(encoded), encoded} {
		got, err := decodeScopes(value)
		if err != nil {
			t.Fatalf("decodeScopes(%T) error = %v", value, err)
		}
		if len(got) != 2 || got[0] != "cards:read" || got[1] != "cards:write" {
			t.Fatalf("decodeScopes(%T) = %v", value, got)
		}
	}
}

func TestParseNullableTime(t *testing.T) {
	t.Parallel()

	got, err := parseNullableTime(nil)
	if err != nil {
		t.Fatalf("parseNullableTime(nil) error = %v", err)
	}
	if got != nil {
		t.Fatalf("parseNullableTime(nil) = %v, want nil", got)
	}

	got, err = parseNullableTime([]byte("2026-06-05 12:00:00.000000"))
	if err != nil {
		t.Fatalf("parseNullableTime(bytes) error = %v", err)
	}
	if got == nil || !got.Equal(fixedMySQLTime()) {
		t.Fatalf("parseNullableTime(bytes) = %v, want %v", got, fixedMySQLTime())
	}
}

func TestMapWriteErrorUsesMySQLNumbers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		number uint16
		want   error
	}{
		{name: "foreign key", number: 1452, want: auth.ErrNotFound},
		{name: "duplicate", number: 1062, want: auth.ErrAlreadyExists},
		{name: "mysql check", number: 3819, want: auth.ErrInvalidState},
		{name: "mariadb check", number: 4025, want: auth.ErrInvalidState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := mapWriteError(&mysqldriver.MySQLError{Number: tt.number})
			if !errors.Is(err, tt.want) {
				t.Fatalf("mapWriteError(%d) = %v, want %v", tt.number, err, tt.want)
			}
		})
	}
}

func fixedMySQLTime() time.Time {
	return time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
}
