package store

import (
	"context"
	"errors"
	"fmt"
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

// Operation IDs are scoped to their account: the same ID on two accounts never conflicts
// (security review of #10).
func TestOperationIDsAreScopedToTheAccount(t *testing.T) {
	v, a1 := vaultAccount(t)
	ctx := context.Background()
	if err := v.CreateAccount(ctx, &Account{ID: "ac2", AssetID: "as", Name: "other", AccountKind: "managed"}); err != nil {
		t.Fatal(err)
	}
	for _, acct := range []string{a1, "ac2"} {
		ver, err := v.Reserve(ctx, acct, "same-op", 0)
		if err != nil {
			t.Fatalf("%s: %v", acct, err)
		}
		if err := v.RecordIntent(ctx, &RotationRun{OperationID: "same-op", AccountID: acct, BrokerID: "b", SecretVersion: ver, Intent: []byte("{\"a\":\"" + acct + "\"}")}); err != nil {
			t.Fatalf("%s intent: %v", acct, err)
		}
	}
}

// The paged chain queries read only the requested slice of an account's history (PR
// Reviewer Guide on #10): a version range with a limit, the open chains, or one envelope.
func TestChainQueriesReadOnlyTheirSlice(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	// v1 release (current), v2 abort, v3 no receipt, v4 commit_target, v5 abort, v6 no receipt.
	ends := []string{"release", "abort", "", "commit_target", "abort", ""}
	for i, end := range ends {
		op, id := fmt.Sprint("op", i+1), fmt.Sprint("e", i+1)
		ver, err := v.Reserve(ctx, acct, op, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.PutEnvelope(ctx, op, &StoredEnvelope{EnvelopeID: id, AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "d" + id, Envelope: []byte(id)}); err != nil {
			t.Fatal(err)
		}
		var rs []*StoredReceipt
		if end != "" {
			rs = append(rs, &StoredReceipt{EnvelopeID: id, ReceiptSeq: 1, ReceiptType: end, OperationID: op, Digest: "h" + id, PrevReceiptHash: zeroHash, Receipt: []byte("r" + id)})
		}
		current := ""
		if i == 0 {
			current = id
		}
		if err := v.Complete(ctx, op, acct, rs, current, "", true); err != nil {
			t.Fatal(err)
		}
	}
	ids := func(cs []*StoredChain) (out []string) {
		for _, c := range cs {
			out = append(out, fmt.Sprintf("%s/%d", c.Envelope.EnvelopeID, len(c.Receipts)))
		}
		return out
	}
	for _, tc := range []struct {
		after uint64
		limit int
		want  string
	}{{2, 2, "[e3/0 e4/1]"}, {0, 1, "[e1/1]"}, {4, 10, "[e5/1 e6/0]"}, {6, 10, "[]"}} {
		cs, err := v.ChainsAfter(ctx, acct, tc.after, tc.limit)
		if err != nil || fmt.Sprint(ids(cs)) != tc.want {
			t.Fatalf("ChainsAfter(%d, %d) = %v %v, want %s", tc.after, tc.limit, ids(cs), err, tc.want)
		}
	}
	if cs, err := v.OpenChains(ctx, acct, 5); err != nil || fmt.Sprint(ids(cs)) != "[e1/1 e3/0 e4/1]" {
		t.Fatalf("OpenChains = %v %v", ids(cs), err)
	}
	if c, err := v.Chain(ctx, acct, "e4"); err != nil || c.Envelope.SecretVersion != 4 || len(c.Receipts) != 1 || string(c.Receipts[0].Receipt) != "re4" {
		t.Fatalf("Chain(e4) = %+v %v", c, err)
	}
	if _, err := v.Chain(ctx, acct, "e9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown envelope: %v", err)
	}
	if _, err := v.Chain(ctx, "other", "e4"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("another account's envelope: %v", err)
	}
}
