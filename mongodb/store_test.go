package mongodb

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	auth "github.com/lechefran/auth"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	_ auth.PrincipalStore = (*Store)(nil)
	_ auth.APIKeyStore    = (*Store)(nil)
	_ auth.AuditStore     = (*Store)(nil)

	_ auth.PrincipalStore         = (*TransactionalStore)(nil)
	_ auth.APIKeyStore            = (*TransactionalStore)(nil)
	_ auth.AuditStore             = (*TransactionalStore)(nil)
	_ auth.AtomicAPIKeyAuditStore = (*TransactionalStore)(nil)
)

func TestPrincipalDocumentRoundTrip(t *testing.T) {
	t.Parallel()

	disabledAt := fixedMongoTime().Add(time.Hour)
	principal := auth.Principal{
		ID:         "user_123",
		Type:       auth.PrincipalTypeUser,
		Name:       "Test User",
		CreatedAt:  fixedMongoTime(),
		UpdatedAt:  fixedMongoTime().Add(time.Minute),
		DisabledAt: &disabledAt,
	}

	doc := principalDocumentFromAuth(principal)
	if doc.DocumentID != "user:user_123" {
		t.Fatalf("DocumentID = %q, want user:user_123", doc.DocumentID)
	}
	got := doc.authPrincipal()
	if got.ID != principal.ID || got.Type != principal.Type || got.Name != principal.Name {
		t.Fatalf("authPrincipal() = %+v, want %+v", got, principal)
	}
	if got.DisabledAt == nil || !got.DisabledAt.Equal(disabledAt) {
		t.Fatalf("DisabledAt = %v, want %v", got.DisabledAt, disabledAt)
	}
}

func TestAPIKeyDocumentRoundTripCopiesSensitiveSlices(t *testing.T) {
	t.Parallel()

	key := auth.APIKey{
		ID:        "key_123",
		Issuer:    "issuer",
		Prefix:    "ak_public",
		Name:      "test key",
		OwnerType: auth.PrincipalTypeUser,
		OwnerID:   "user_123",
		Hash:      []byte("hash"),
		Scopes:    []string{"cards:read", "cards:write"},
		CreatedAt: fixedMongoTime(),
	}

	doc := apiKeyDocumentFromAuth(key)
	key.Hash[0] ^= 0xff
	key.Scopes[0] = "mutated"
	got := doc.authAPIKey()

	if !bytes.Equal(got.Hash, []byte("hash")) {
		t.Fatalf("Hash = %q, want original hash", string(got.Hash))
	}
	if got.Scopes[0] != "cards:read" {
		t.Fatalf("Scopes = %v, want original scopes", got.Scopes)
	}

	got.Hash[0] ^= 0xff
	again := doc.authAPIKey()
	if bytes.Equal(got.Hash, again.Hash) {
		t.Fatal("authAPIKey() returned caller-owned hash slice")
	}
}

func TestAuditEventDocumentDefaultsMetadata(t *testing.T) {
	t.Parallel()

	doc := auditEventDocumentFromAuth(auth.AuditEvent{
		ID:       "event_123",
		Type:     auth.AuditEventAPIKeyCreated,
		Occurred: fixedMongoTime(),
	})
	if doc.DocumentID != "event_123" {
		t.Fatalf("DocumentID = %q, want event_123", doc.DocumentID)
	}
	if doc.Metadata == nil {
		t.Fatal("Metadata = nil, want empty map")
	}
}

func TestStoreCursorRoundTrip(t *testing.T) {
	t.Parallel()

	want := cursorValue{
		CreatedAt: fixedMongoTime().Format(time.RFC3339Nano),
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

func TestMapWriteErrorUsesMongoErrors(t *testing.T) {
	t.Parallel()

	duplicate := mongo.WriteException{
		WriteErrors: mongo.WriteErrors{{Code: 11000, Message: "duplicate key"}},
	}
	if err := mapWriteError(duplicate); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("mapWriteError(duplicate) = %v, want ErrAlreadyExists", err)
	}

	validation := mongo.CommandError{Code: 121}
	if err := mapWriteError(validation); !errors.Is(err, auth.ErrInvalidState) {
		t.Fatalf("mapWriteError(validation) = %v, want ErrInvalidState", err)
	}
}

func TestSimpleCollation(t *testing.T) {
	t.Parallel()

	collation := simpleCollation()
	if collation == nil || collation.Locale != "simple" {
		t.Fatalf("simpleCollation() = %+v, want locale simple", collation)
	}
}

func fixedMongoTime() time.Time {
	return time.Date(2026, 6, 5, 12, 0, 0, 0, time.UTC)
}
