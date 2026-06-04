// Package password provides password hashing and verification helpers.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	algorithmArgon2id = "argon2id"
	argon2Version     = argon2.Version

	defaultMemoryKiB   = 64 * 1024
	defaultIterations  = 3
	defaultParallelism = 4
	defaultSaltLength  = 16
	defaultKeyLength   = 32

	minMemoryKiB   = 19 * 1024
	minIterations  = 2
	minParallelism = 1
	minSaltLength  = 16
	minKeyLength   = 16
)

var (
	// ErrInvalidHash reports that an encoded password hash is malformed.
	ErrInvalidHash = errors.New("password: invalid hash")

	// ErrUnsupportedHash reports that an encoded password hash uses an
	// unsupported algorithm or version.
	ErrUnsupportedHash = errors.New("password: unsupported hash")

	// ErrInvalidParams reports unsafe or incomplete hashing parameters.
	ErrInvalidParams = errors.New("password: invalid params")

	// ErrEmptyPassword reports that a password value was empty.
	ErrEmptyPassword = errors.New("password: empty password")
)

// Params controls Argon2id password hashing.
//
// MemoryKiB is measured in kibibytes. The defaults are intended for production
// use and can be increased as hardware allows.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams returns the secure default Argon2id parameters.
func DefaultParams() Params {
	return Params{
		MemoryKiB:   defaultMemoryKiB,
		Iterations:  defaultIterations,
		Parallelism: defaultParallelism,
		SaltLength:  defaultSaltLength,
		KeyLength:   defaultKeyLength,
	}
}

// Validate rejects incomplete or unsafe Argon2id parameters.
func (p Params) Validate() error {
	if p.MemoryKiB < minMemoryKiB {
		return errors.Join(ErrInvalidParams, fmt.Errorf("memory must be at least %d KiB", minMemoryKiB))
	}
	if p.Iterations < minIterations {
		return errors.Join(ErrInvalidParams, fmt.Errorf("iterations must be at least %d", minIterations))
	}
	if p.Parallelism < minParallelism {
		return errors.Join(ErrInvalidParams, fmt.Errorf("parallelism must be at least %d", minParallelism))
	}
	if p.SaltLength < minSaltLength {
		return errors.Join(ErrInvalidParams, fmt.Errorf("salt length must be at least %d bytes", minSaltLength))
	}
	if p.KeyLength < minKeyLength {
		return errors.Join(ErrInvalidParams, fmt.Errorf("key length must be at least %d bytes", minKeyLength))
	}
	return nil
}

// Hasher hashes and verifies passwords using Argon2id.
type Hasher struct {
	params Params
}

// Argon2id returns a password hasher using the secure default parameters.
func Argon2id() *Hasher {
	return &Hasher{params: DefaultParams()}
}

// NewArgon2id returns a password hasher using caller-supplied parameters.
func NewArgon2id(params Params) (*Hasher, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	return &Hasher{params: params}, nil
}

// Params returns the hasher's Argon2id parameters.
func (h *Hasher) Params() Params {
	return h.params
}

// Hash returns a PHC-formatted Argon2id password hash.
func (h *Hasher) Hash(password []byte) (string, error) {
	if len(password) == 0 {
		return "", ErrEmptyPassword
	}
	if err := h.params.Validate(); err != nil {
		return "", err
	}

	salt := make([]byte, h.params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey(password, salt, h.params.Iterations, h.params.MemoryKiB, h.params.Parallelism, h.params.KeyLength)
	return encodePHC(h.params, salt, key), nil
}

// Verify compares a password with a PHC-formatted Argon2id hash.
//
// needsRehash is true when the password matched but the stored hash uses weaker
// parameters than this hasher.
func (h *Hasher) Verify(encoded string, password []byte) (matched bool, needsRehash bool, err error) {
	if len(password) == 0 {
		return false, false, ErrEmptyPassword
	}
	if err := h.params.Validate(); err != nil {
		return false, false, err
	}

	stored, err := decodePHC(encoded)
	if err != nil {
		return false, false, err
	}

	key := argon2.IDKey(password, stored.salt, stored.params.Iterations, stored.params.MemoryKiB, stored.params.Parallelism, uint32(len(stored.key)))
	if subtle.ConstantTimeCompare(key, stored.key) != 1 {
		return false, false, nil
	}

	return true, h.needsRehash(stored.params), nil
}

func (h *Hasher) needsRehash(stored Params) bool {
	return stored.MemoryKiB < h.params.MemoryKiB ||
		stored.Iterations < h.params.Iterations ||
		stored.Parallelism < h.params.Parallelism ||
		stored.SaltLength < h.params.SaltLength ||
		stored.KeyLength < h.params.KeyLength
}

type decodedHash struct {
	params Params
	salt   []byte
	key    []byte
}

func encodePHC(params Params, salt []byte, key []byte) string {
	return fmt.Sprintf(
		"$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		algorithmArgon2id,
		argon2Version,
		params.MemoryKiB,
		params.Iterations,
		params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

func decodePHC(encoded string) (decodedHash, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" {
		return decodedHash{}, ErrInvalidHash
	}
	if parts[1] != algorithmArgon2id {
		return decodedHash{}, errors.Join(ErrUnsupportedHash, fmt.Errorf("algorithm %q", parts[1]))
	}

	version, err := parseVersion(parts[2])
	if err != nil {
		return decodedHash{}, err
	}
	if version != argon2Version {
		return decodedHash{}, errors.Join(ErrUnsupportedHash, fmt.Errorf("version %d", version))
	}

	params, err := parseParams(parts[3])
	if err != nil {
		return decodedHash{}, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return decodedHash{}, errors.Join(ErrInvalidHash, errors.New("invalid salt encoding"))
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return decodedHash{}, errors.Join(ErrInvalidHash, errors.New("invalid key encoding"))
	}

	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	if err := params.Validate(); err != nil {
		return decodedHash{}, err
	}

	return decodedHash{
		params: params,
		salt:   salt,
		key:    key,
	}, nil
}

func parseVersion(value string) (int, error) {
	if !strings.HasPrefix(value, "v=") {
		return 0, ErrInvalidHash
	}
	version, err := strconv.Atoi(strings.TrimPrefix(value, "v="))
	if err != nil {
		return 0, errors.Join(ErrInvalidHash, errors.New("invalid version"))
	}
	return version, nil
}

func parseParams(value string) (Params, error) {
	fields := strings.Split(value, ",")
	if len(fields) != 3 {
		return Params{}, ErrInvalidHash
	}

	var params Params
	for _, field := range fields {
		name, raw, ok := strings.Cut(field, "=")
		if !ok {
			return Params{}, ErrInvalidHash
		}
		parsed, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			return Params{}, errors.Join(ErrInvalidHash, fmt.Errorf("invalid %s parameter", name))
		}

		switch name {
		case "m":
			params.MemoryKiB = uint32(parsed)
		case "t":
			params.Iterations = uint32(parsed)
		case "p":
			if parsed > uint64(^uint8(0)) {
				return Params{}, errors.Join(ErrInvalidHash, errors.New("parallelism parameter is too large"))
			}
			params.Parallelism = uint8(parsed)
		default:
			return Params{}, errors.Join(ErrInvalidHash, fmt.Errorf("unknown parameter %q", name))
		}
	}

	return params, nil
}
