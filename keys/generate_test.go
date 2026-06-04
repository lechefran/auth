package keys

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestGenerateHMACKey(t *testing.T) {
	t.Parallel()

	first, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}
	second, err := GenerateHMACKey()
	if err != nil {
		t.Fatalf("GenerateHMACKey() error = %v", err)
	}

	if len(first) != defaultHMACKeyBytes {
		t.Fatalf("GenerateHMACKey() length = %d, want %d", len(first), defaultHMACKeyBytes)
	}
	if string(first) == string(second) {
		t.Fatal("GenerateHMACKey() returned duplicate values")
	}
}

func TestGenerateSymmetricKeyRejectsShortLength(t *testing.T) {
	t.Parallel()

	_, err := GenerateSymmetricKey(minKeyBytes - 1)
	if !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("GenerateSymmetricKey() error = %v, want ErrInvalidLength", err)
	}
}

func TestGenerateEd25519KeyPairSignsAndVerifies(t *testing.T) {
	t.Parallel()

	publicKey, privateKey, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair() error = %v", err)
	}

	message := []byte("test message")
	signature := ed25519.Sign(privateKey, message)
	if !ed25519.Verify(publicKey, message, signature) {
		t.Fatal("ed25519 signature did not verify")
	}
}
