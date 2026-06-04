package auth

// PasswordHasher hashes and verifies password credentials.
type PasswordHasher interface {
	Hash(password []byte) (string, error)
	Verify(encoded string, password []byte) (matched bool, needsRehash bool, err error)
}
