package token

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateOpaqueReturnsDistinctURLSafeValues(t *testing.T) {
	t.Parallel()

	first, err := GenerateAPIKeySecret()
	if err != nil {
		t.Fatalf("GenerateAPIKeySecret() error = %v", err)
	}
	second, err := GenerateAPIKeySecret()
	if err != nil {
		t.Fatalf("GenerateAPIKeySecret() error = %v", err)
	}

	if first == second {
		t.Fatal("GenerateAPIKeySecret() returned duplicate values")
	}
	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("GenerateAPIKeySecret() = %q, want raw URL-safe base64", first)
	}
}

func TestGenerateRejectsShortLength(t *testing.T) {
	t.Parallel()

	_, err := GenerateOpaque(minTokenBytes - 1)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("GenerateOpaque() error = %v, want ErrInvalidLength", err)
	}
}

func TestLookupHash(t *testing.T) {
	t.Parallel()

	first, err := LookupHash("token-one")
	if err != nil {
		t.Fatalf("LookupHash() error = %v", err)
	}
	second, err := LookupHash("token-one")
	if err != nil {
		t.Fatalf("LookupHash() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("LookupHash() is not deterministic")
	}

	other, err := LookupHash("token-two")
	if err != nil {
		t.Fatalf("LookupHash() error = %v", err)
	}
	if string(first) == string(other) {
		t.Fatal("LookupHash() returned same hash for different tokens")
	}
}

func TestLookupHashRejectsEmptyToken(t *testing.T) {
	t.Parallel()

	_, err := LookupHash("")
	if !errors.Is(err, ErrEmptyToken) {
		t.Fatalf("LookupHash() error = %v, want ErrEmptyToken", err)
	}
}

func TestHMACLookupHash(t *testing.T) {
	t.Parallel()

	key := []byte("01234567890123456789012345678901")
	first, err := HMACLookupHash("token-one", key)
	if err != nil {
		t.Fatalf("HMACLookupHash() error = %v", err)
	}
	second, err := HMACLookupHash("token-one", key)
	if err != nil {
		t.Fatalf("HMACLookupHash() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("HMACLookupHash() is not deterministic")
	}
}

func TestHMACLookupHashRejectsWeakKey(t *testing.T) {
	t.Parallel()

	_, err := HMACLookupHash("token-one", []byte("short"))
	if !errors.Is(err, ErrWeakLookupKey) {
		t.Fatalf("HMACLookupHash() error = %v, want ErrWeakLookupKey", err)
	}
}
