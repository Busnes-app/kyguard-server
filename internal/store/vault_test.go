package store

import (
	"context"
	"errors"
	"testing"
)

func vaultAccount(t *testing.T) (VaultStore, string) {
	t.Helper()
	s, _ := guardStoreFor(t)
	v := s.Vault()
	ctx := context.Background()
	if err := v.CreateAsset(ctx, &Asset{ID: "as", Name: "host"}); err != nil {
		t.Fatal(err)
	}
	if err := v.CreateAccount(ctx, &Account{ID: "ac", AssetID: "as", Name: "svc", AccountKind: "managed"}); err != nil {
		t.Fatal(err)
	}
	return v, "ac"
}

func TestCompleteReleasesOnlyItsOwnLock(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	if _, err := v.Reserve(ctx, acct, "op-b", 0); err != nil {
		t.Fatal(err)
	}
	if err := v.Complete(ctx, "op-a", acct, nil, "", "", true); err != nil {
		t.Fatal(err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "op-b" {
		t.Fatalf("lock held by %q", op)
	}
	if err := v.Complete(ctx, "op-b", acct, nil, "", "", true); err != nil {
		t.Fatal(err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "" {
		t.Fatalf("lock held by %q", op)
	}
}

// The store's own compare-and-swap, for writers that verified against the same stale head.
func TestReceiptAppendCASInTheStore(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	ver, _ := v.Reserve(ctx, acct, "op", 0)
	if err := v.PutEnvelope(ctx, "op", &StoredEnvelope{EnvelopeID: "e", AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "de", Envelope: []byte("{}")}); err != nil {
		t.Fatal(err)
	}
	r1 := &StoredReceipt{EnvelopeID: "e", ReceiptSeq: 1, ReceiptType: "commit_target", OperationID: "op", Digest: "h1", PrevReceiptHash: zeroHash, Receipt: []byte("r1")}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r1}, "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r1}, "", "", false); err != nil {
		t.Fatalf("identical re-append: %v", err)
	}
	fork := *r1
	fork.Receipt, fork.Digest = []byte("other"), "hx"
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{&fork}, "", "", false); !errors.Is(err, ErrConflict) {
		t.Fatalf("fork: %v", err)
	}
	for _, bad := range []*StoredReceipt{
		{EnvelopeID: "e", ReceiptSeq: 2, ReceiptType: "release", OperationID: "op", Digest: "h2", PrevReceiptHash: zeroHash, Receipt: []byte("r2")},
		{EnvelopeID: "e", ReceiptSeq: 3, ReceiptType: "release", OperationID: "op", Digest: "h3", PrevReceiptHash: "h1", Receipt: []byte("r3")},
	} {
		if err := v.Complete(ctx, "op", acct, []*StoredReceipt{bad}, "e", "", true); !errors.Is(err, ErrConflict) {
			t.Fatalf("seq %d: %v", bad.ReceiptSeq, err)
		}
	}
	// A refused completion changed nothing: not current, lock still held.
	if a, _ := v.GetAccount(ctx, acct); a.CurrentEnvelopeID != "" {
		t.Fatalf("current %q", a.CurrentEnvelopeID)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "op" {
		t.Fatalf("lock %q", op)
	}
}
