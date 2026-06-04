package auth

import "errors"

var (
	// ErrNotFound reports that a requested record does not exist.
	ErrNotFound = errors.New("auth: not found")

	// ErrAlreadyExists reports that creating a record would violate uniqueness.
	ErrAlreadyExists = errors.New("auth: already exists")

	// ErrConflict reports that a write could not be applied because the stored
	// state changed or conflicts with the requested state.
	ErrConflict = errors.New("auth: conflict")

	// ErrInvalidState reports that a requested transition is not allowed for the
	// current resource state, such as revoking an already-revoked token.
	ErrInvalidState = errors.New("auth: invalid state")
)
