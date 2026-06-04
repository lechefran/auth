// Package keys provides secure signing and symmetric key generation.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	defaultHMACKeyBytes = 32
	minKeyBytes         = 32
)

var (
	// ErrInvalidLength reports an unsafe key byte length.
	ErrInvalidLength = errors.New("keys: invalid length")
)

// GenerateSymmetricKey returns random bytes suitable for HMAC or encryption
// key material, depending on the caller's protocol.
func GenerateSymmetricKey(byteLength int) ([]byte, error) {
	if byteLength < minKeyBytes {
		return nil, errors.Join(ErrInvalidLength, fmt.Errorf("length must be at least %d bytes", minKeyBytes))
	}

	key := make([]byte, byteLength)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate symmetric key: %w", err)
	}
	return key, nil
}

// GenerateHMACKey returns a 256-bit random key suitable for HMAC-SHA-256.
func GenerateHMACKey() ([]byte, error) {
	return GenerateSymmetricKey(defaultHMACKeyBytes)
}

// GenerateEd25519KeyPair returns a new Ed25519 signing key pair.
func GenerateEd25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 key pair: %w", err)
	}
	return publicKey, privateKey, nil
}
