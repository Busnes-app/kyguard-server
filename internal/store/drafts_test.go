package store

import (
	"context"
	"errors"
	"testing"
)

// Two signature submissions read the same draft; the second must not overwrite the
// signatures the first stored (the digest leaves signatures out, so it cannot tell).
func TestDraftObjectCompareAndSwap(t *testing.T) {
	s, _ := inventoryFor(t)
	ctx := context.Background()
	d := &PolicyDraft{ID: "pd", AccountID: "ac", Epoch: 1, Digest: "dg", Object: []byte(`{"signatures":[]}`), CreatedBy: "usr_a"}
	if err := s.Drafts().PutDraft(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	snapshot := d.Object
	first := []byte(`{"signatures":["a"]}`)
	if err := s.Drafts().SetDraftObject(ctx, "pd", snapshot, first, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Drafts().SetDraftObject(ctx, "pd", snapshot, []byte(`{"signatures":["b"]}`), nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale update: %v", err)
	}
	got, err := s.Drafts().GetDraft(ctx, "pd")
	if err != nil || string(got.Object) != string(first) {
		t.Fatalf("stored %s %v", got.Object, err)
	}
}
