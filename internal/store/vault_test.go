package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
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
	if cs, err := v.OpenChains(ctx, acct, 0, 5, 10); err != nil || fmt.Sprint(ids(cs)) != "[e1/1 e3/0 e4/1]" {
		t.Fatalf("OpenChains = %v %v", ids(cs), err)
	}
	if cs, err := v.OpenChains(ctx, acct, 1, 5, 1); err != nil || fmt.Sprint(ids(cs)) != "[e3/0]" {
		t.Fatalf("OpenChains(1, 5, 1) = %v %v", ids(cs), err)
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

// A completion delayed past a newer rotation is a retry: it neither rewinds the current
// envelope nor the run state (PR Reviewer Guide on #10).
func TestADelayedDuplicateCompletionChangesNothing(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	release := func(op, id string) []*StoredReceipt {
		ver, err := v.Reserve(ctx, acct, op, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.PutEnvelope(ctx, op, &StoredEnvelope{EnvelopeID: id, AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "d" + id, Envelope: []byte(id)}); err != nil {
			t.Fatal(err)
		}
		if err := v.RecordIntent(ctx, &RotationRun{OperationID: op, AccountID: acct, BrokerID: "b", SecretVersion: ver, Intent: []byte("i" + op)}); err != nil {
			t.Fatal(err)
		}
		rs := []*StoredReceipt{{EnvelopeID: id, ReceiptSeq: 1, ReceiptType: "release", OperationID: op, Digest: "h" + id, PrevReceiptHash: zeroHash, Receipt: []byte("r" + id)}}
		if err := v.Complete(ctx, op, acct, rs, id, "release_authorized", true); err != nil {
			t.Fatal(err)
		}
		return rs
	}
	old := release("op1", "e1")
	release("op2", "e2")
	if err := v.Complete(ctx, "op1", acct, old, "e1", "target_verified", true); err != nil {
		t.Fatal(err)
	}
	if a, _ := v.GetAccount(ctx, acct); a.CurrentEnvelopeID != "e2" {
		t.Fatalf("current %q after a delayed duplicate, want e2", a.CurrentEnvelopeID)
	}
	if r, _ := v.GetRun(ctx, acct, "op1"); r.State != "release_authorized" {
		t.Fatalf("run state %q after a delayed duplicate", r.State)
	}
}

// One chain and one descriptor stay under their caps, so a sync reply always fits a frame
// (security review of #10).
func TestChainsAndDescriptorsAreCapped(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	if err := v.PutTargetDescriptor(ctx, "td", acct, make([]byte, MaxDescriptor+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized descriptor: %v", err)
	}
	ver, _ := v.Reserve(ctx, acct, "op", 0)
	if err := v.PutEnvelope(ctx, "op", &StoredEnvelope{EnvelopeID: "big", AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "dbig", Envelope: make([]byte, MaxEnvelope+1)}); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized envelope: %v", err)
	}
	env := []byte(strings.Repeat("e", MaxChain/2))
	if err := v.PutEnvelope(ctx, "op", &StoredEnvelope{EnvelopeID: "e", AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "de", Envelope: env}); err != nil {
		t.Fatal(err)
	}
	r := func(seq uint64, prev string, n int) *StoredReceipt {
		return &StoredReceipt{EnvelopeID: "e", ReceiptSeq: seq, ReceiptType: "commit_target", OperationID: "op", Digest: fmt.Sprint("h", seq), PrevReceiptHash: prev, Receipt: []byte(strings.Repeat("r", n))}
	}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r(1, zeroHash, MaxChain/4)}, "", "", false); err != nil {
		t.Fatal(err)
	}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r(2, "h1", MaxChain/4+1)}, "", "", false); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("receipt over the chain cap: %v", err)
	}
}

// Concurrent identical retries of an envelope store and an intent all succeed: the
// account lock is taken before the existence check (PR Reviewer Guide on #10).
func TestConcurrentIdenticalRetriesSucceed(t *testing.T) {
	v, a := vaultAccount(t)
	ctx := context.Background()
	ver, err := v.Reserve(ctx, a, "op", 0)
	if err != nil {
		t.Fatal(err)
	}
	e := &StoredEnvelope{EnvelopeID: "env", AccountID: a, SecretVersion: ver, EnvelopeKind: "managed", Digest: "d", Envelope: []byte("{}")}
	run := &RotationRun{OperationID: "op", AccountID: a, BrokerID: "b", SecretVersion: ver, Intent: []byte(`{"i":1}`)}
	var wg sync.WaitGroup
	errs := make([]error, 16)
	for i := range errs {
		wg.Go(func() {
			if i%2 == 0 {
				errs[i] = v.PutEnvelope(ctx, "op", e)
			} else {
				errs[i] = v.RecordIntent(ctx, run)
			}
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("retry %d: %v", i, err)
		}
	}
}

// The largest envelope the store takes still leaves room for its terminal receipt, so an
// accepted enrollment can always be finished and its lock released (security review of #15).
func TestTheLargestEnvelopeCanStillBeFinished(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	ver, _ := v.Reserve(ctx, acct, "op", 0)
	if err := v.PutEnvelope(ctx, "op", &StoredEnvelope{EnvelopeID: "e", AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "de", Envelope: []byte(strings.Repeat("e", MaxEnvelope))}); err != nil {
		t.Fatal(err)
	}
	abort := &StoredReceipt{EnvelopeID: "e", ReceiptSeq: 1, ReceiptType: "abort", OperationID: "op", Digest: "h1", PrevReceiptHash: zeroHash, Receipt: []byte(strings.Repeat("r", 16<<10))}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{abort}, "", "", true); err != nil {
		t.Fatalf("terminal receipt after the largest envelope: %v", err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "" {
		t.Fatalf("lock still held by %s", op)
	}
}
