package auth

const (
	// DefaultPageLimit is used when callers do not provide a limit.
	DefaultPageLimit = 50

	// MaxPageLimit is the largest page size accepted by core workflows.
	MaxPageLimit = 200

	maxCursorLength = 1024
)

// PageRequest requests a bounded page of results after Cursor.
//
// Cursor is an opaque value returned by a previous page. Stores define the
// cursor encoding, but callers must pass it through unchanged.
type PageRequest struct {
	Limit  int
	Cursor string
}

// Page contains one page of items and the cursor for the next page.
//
// NextCursor is empty when there are no more results.
type Page[T any] struct {
	Items      []T
	NextCursor string
}

// HasMore reports whether another page is available.
func (p Page[T]) HasMore() bool {
	return p.NextCursor != ""
}

func normalizePageRequest(req PageRequest) (PageRequest, error) {
	if req.Limit < 0 {
		return PageRequest{}, ErrInvalidRequest
	}
	if req.Limit == 0 {
		req.Limit = DefaultPageLimit
	}
	if req.Limit > MaxPageLimit {
		req.Limit = MaxPageLimit
	}
	if !isValidCursor(req.Cursor) {
		return PageRequest{}, ErrInvalidRequest
	}
	return req, nil
}

func isValidCursor(cursor string) bool {
	if len(cursor) > maxCursorLength {
		return false
	}
	for _, r := range cursor {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}
