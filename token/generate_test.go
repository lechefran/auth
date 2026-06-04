package token

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateReturnsDistinctURLSafeTokens(t *testing.T) {
	t.Parallel()

	first, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}
	second, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if first == second {
		t.Fatal("GenerateSessionID() returned duplicate values")
	}
	if strings.ContainsAny(first, "+/=") {
		t.Fatalf("GenerateSessionID() = %q, want raw URL-safe base64", first)
	}
}

func TestGenerateRejectsShortLength(t *testing.T) {
	t.Parallel()

	_, err := Generate(minTokenBytes - 1)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("Generate() error = %v, want ErrInvalidLength", err)
	}
}

func TestGenerateRecoveryCodeIsGrouped(t *testing.T) {
	t.Parallel()

	code, err := GenerateRecoveryCode()
	if err != nil {
		t.Fatalf("GenerateRecoveryCode() error = %v", err)
	}

	parts := strings.Split(code, "-")
	if len(parts) != 4 {
		t.Fatalf("GenerateRecoveryCode() = %q, want 4 groups", code)
	}
	for _, part := range parts {
		if len(part) != recoveryCodeGroupSize {
			t.Fatalf("GenerateRecoveryCode() group = %q, want length %d", part, recoveryCodeGroupSize)
		}
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
