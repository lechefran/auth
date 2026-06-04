package auth

import "testing"

func TestPageHasMore(t *testing.T) {
	t.Parallel()

	if (Page[int]{}).HasMore() {
		t.Fatal("empty page HasMore() = true, want false")
	}
	if !(Page[int]{NextCursor: "next"}).HasMore() {
		t.Fatal("page with cursor HasMore() = false, want true")
	}
}

func TestNormalizePageRequest(t *testing.T) {
	t.Parallel()

	page, err := normalizePageRequest(PageRequest{})
	if err != nil {
		t.Fatalf("normalizePageRequest(default) error = %v", err)
	}
	if page.Limit != DefaultPageLimit {
		t.Fatalf("default limit = %d, want %d", page.Limit, DefaultPageLimit)
	}

	page, err = normalizePageRequest(PageRequest{Limit: MaxPageLimit + 1})
	if err != nil {
		t.Fatalf("normalizePageRequest(max) error = %v", err)
	}
	if page.Limit != MaxPageLimit {
		t.Fatalf("max limit = %d, want %d", page.Limit, MaxPageLimit)
	}
}
