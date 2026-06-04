package password

import (
	"errors"
	"strings"
	"testing"
)

func TestArgon2idHashAndVerify(t *testing.T) {
	t.Parallel()

	hasher := testHasher(t, testParams())
	encoded, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	if !strings.HasPrefix(encoded, "$argon2id$v=19$") {
		t.Fatalf("Hash() = %q, want PHC argon2id prefix", encoded)
	}

	matched, needsRehash, err := hasher.Verify(encoded, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !matched {
		t.Fatal("Verify() matched = false, want true")
	}
	if needsRehash {
		t.Fatal("Verify() needsRehash = true, want false")
	}
}

func TestArgon2idVerifyRejectsWrongPassword(t *testing.T) {
	t.Parallel()

	hasher := testHasher(t, testParams())
	encoded, err := hasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	matched, needsRehash, err := hasher.Verify(encoded, []byte("wrong password"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if matched {
		t.Fatal("Verify() matched = true, want false")
	}
	if needsRehash {
		t.Fatal("Verify() needsRehash = true, want false")
	}
}

func TestArgon2idVerifyReportsRehash(t *testing.T) {
	t.Parallel()

	oldHasher := testHasher(t, testParams())
	encoded, err := oldHasher.Hash([]byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}

	stronger := testParams()
	stronger.Iterations++
	newHasher := testHasher(t, stronger)

	matched, needsRehash, err := newHasher.Verify(encoded, []byte("correct horse battery staple"))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if !matched {
		t.Fatal("Verify() matched = false, want true")
	}
	if !needsRehash {
		t.Fatal("Verify() needsRehash = false, want true")
	}
}

func TestArgon2idRejectsEmptyPassword(t *testing.T) {
	t.Parallel()

	hasher := testHasher(t, testParams())

	if _, err := hasher.Hash(nil); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Hash(nil) error = %v, want ErrEmptyPassword", err)
	}

	if _, _, err := hasher.Verify("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAA", nil); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Verify(empty) error = %v, want ErrEmptyPassword", err)
	}
}

func TestArgon2idRejectsInvalidParams(t *testing.T) {
	t.Parallel()

	_, err := NewArgon2id(Params{
		MemoryKiB:   minMemoryKiB - 1,
		Iterations:  minIterations,
		Parallelism: minParallelism,
		SaltLength:  minSaltLength,
		KeyLength:   minKeyLength,
	})
	if !errors.Is(err, ErrInvalidParams) {
		t.Fatalf("NewArgon2id() error = %v, want ErrInvalidParams", err)
	}
}

func TestArgon2idRejectsMalformedHash(t *testing.T) {
	t.Parallel()

	hasher := testHasher(t, testParams())

	_, _, err := hasher.Verify("not-a-phc-hash", []byte("password"))
	if !errors.Is(err, ErrInvalidHash) {
		t.Fatalf("Verify() error = %v, want ErrInvalidHash", err)
	}
}

func TestArgon2idRejectsUnsupportedHash(t *testing.T) {
	t.Parallel()

	hasher := testHasher(t, testParams())

	_, _, err := hasher.Verify("$bcrypt$v=19$m=19456,t=2,p=1$c29tZXNhbHQxMjM0NTY3OA$AAAAAAAAAAAAAAAAAAAAAA", []byte("password"))
	if !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("Verify() error = %v, want ErrUnsupportedHash", err)
	}
}

func testParams() Params {
	return Params{
		MemoryKiB:   minMemoryKiB,
		Iterations:  minIterations,
		Parallelism: minParallelism,
		SaltLength:  minSaltLength,
		KeyLength:   minKeyLength,
	}
}

func testHasher(t *testing.T, params Params) *Hasher {
	t.Helper()

	hasher, err := NewArgon2id(params)
	if err != nil {
		t.Fatalf("NewArgon2id() error = %v", err)
	}
	return hasher
}
