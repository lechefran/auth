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

	// ErrInvalidRequest reports malformed or incomplete caller input.
	ErrInvalidRequest = errors.New("auth: invalid request")

	// ErrInvalidCredentials reports failed authentication without revealing
	// whether an API key prefix, hash, owner, or state was the failing factor.
	ErrInvalidCredentials = errors.New("auth: invalid credentials")

	// ErrDisabledPrincipal reports that an otherwise valid principal is disabled.
	ErrDisabledPrincipal = errors.New("auth: disabled principal")

	// ErrPermissionDenied reports that a valid API key lacks required scope.
	ErrPermissionDenied = errors.New("auth: permission denied")

	// ErrMissingStore reports that a workflow was called without the required
	// storage dependency configured.
	ErrMissingStore = errors.New("auth: missing store")
)
