package store

import (
	"context"
	"errors"
	"testing"
	"time"
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
	if err := v.Complete(ctx, "op-a", acct, nil, "", "", LockDelete); err != nil {
		t.Fatal(err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "op-b" {
		t.Fatalf("lock held by %q", op)
	}
	if err := v.Complete(ctx, "op-b", acct, nil, "", "", LockDelete); err != nil {
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
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r1}, "", "", LockKeep); err != nil {
		t.Fatal(err)
	}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r1}, "", "", LockKeep); err != nil {
		t.Fatalf("identical re-append: %v", err)
	}
	fork := *r1
	fork.Receipt, fork.Digest = []byte("other"), "hx"
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{&fork}, "", "", LockKeep); !errors.Is(err, ErrConflict) {
		t.Fatalf("fork: %v", err)
	}
	for _, bad := range []*StoredReceipt{
		{EnvelopeID: "e", ReceiptSeq: 2, ReceiptType: "release", OperationID: "op", Digest: "h2", PrevReceiptHash: zeroHash, Receipt: []byte("r2")},
		{EnvelopeID: "e", ReceiptSeq: 3, ReceiptType: "release", OperationID: "op", Digest: "h3", PrevReceiptHash: "h1", Receipt: []byte("r3")},
	} {
		if err := v.Complete(ctx, "op", acct, []*StoredReceipt{bad}, "e", "", LockDelete); !errors.Is(err, ErrConflict) {
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

// §4.5 step 1: a reservation needs no lock or a quarantined account; it displaces a stuck
// rotation's lock and gives it back on expiry; an expired reservation cannot be accepted.
func TestEnrollmentReservation(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := v.Reserve(ctx, acct, "rot", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReserveEnrollment(ctx, acct, "enr", 0, now, 15*time.Minute); !errors.Is(err, ErrLocked) {
		t.Fatalf("healthy account with an open rotation: %v", err)
	}
	if err := v.SetHealth(ctx, acct, "quarantined", ""); err != nil {
		t.Fatal(err)
	}
	ver, err := v.ReserveEnrollment(ctx, acct, "enr", 0, now.Add(-16*time.Minute), 15*time.Minute)
	if err != nil || ver != 2 {
		t.Fatalf("quarantined: %v %v", ver, err)
	}
	if _, err := v.ReserveEnrollment(ctx, acct, "enr2", 0, now.Add(-16*time.Minute), 15*time.Minute); !errors.Is(err, ErrLocked) {
		t.Fatalf("a second enrollment: %v", err)
	}
	if err := v.AcceptEnrollment(ctx, acct, "enr", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("accepting an expired reservation: %v", err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "rot" {
		t.Fatalf("lock after expiry %q, want the stuck rotation", op)
	}
	// Accepted reservations never expire.
	if _, err := v.ReserveEnrollment(ctx, acct, "enr3", 0, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := v.AcceptEnrollment(ctx, acct, "enr3", now); err != nil {
		t.Fatal(err)
	}
	if n, err := v.ExpireEnrollments(ctx, now.Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("expired an accepted reservation: %d %v", n, err)
	}
	if err := v.Complete(ctx, "enr3", acct, nil, "", "", LockRestore); err != nil {
		t.Fatal(err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "rot" {
		t.Fatalf("restore gave %q", op)
	}
}

// §3.6 step 3: at most one non-closed lease per account, as a database constraint; a
// closed lease never reopens.
func TestOneOpenLeasePerAccount(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	now := time.Now().UTC()
	l := func(id, state string) *Lease {
		return &Lease{RequestID: id, AccountID: acct, BrokerID: "b", SecretVersion: 1, State: state, OpenedAt: now, ExpiresAt: now.Add(time.Hour)}
	}
	if err := v.MirrorLease(ctx, l("r1", "active")); err != nil {
		t.Fatal(err)
	}
	if err := v.MirrorLease(ctx, l("r2", "active")); !errors.Is(err, ErrConflict) {
		t.Fatalf("second open lease: %v", err)
	}
	if err := v.MirrorLease(ctx, l("r1", "closed")); err != nil {
		t.Fatal(err)
	}
	if err := v.MirrorLease(ctx, l("r1", "active")); !errors.Is(err, ErrConflict) {
		t.Fatalf("reopened: %v", err)
	}
	if err := v.MirrorLease(ctx, l("r2", "active")); err != nil {
		t.Fatalf("after close: %v", err)
	}
}
