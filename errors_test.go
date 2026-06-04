package auth

import (
	"errors"
	"testing"
)

func TestStoreErrorsCanBeWrapped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "not found", err: ErrNotFound},
		{name: "already exists", err: ErrAlreadyExists},
		{name: "conflict", err: ErrConflict},
		{name: "invalid state", err: ErrInvalidState},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			wrapped := errors.Join(tt.err, errors.New("adapter detail"))
			if !errors.Is(wrapped, tt.err) {
				t.Fatalf("errors.Is(%v, %v) = false, want true", wrapped, tt.err)
			}
		})
	}
}
