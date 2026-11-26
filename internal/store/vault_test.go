package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func vaultAccount(t *testing.T) (VaultStore, string) {
	t.Helper()
	v, _, acct := vaultAccountGuard(t)
	return v, acct
}

// vaultAccountGuard also returns the guard store, with policy epoch 1 (digest "p1",
// descriptor "d1") accepted for the account.
func vaultAccountGuard(t *testing.T) (VaultStore, GuardStore, string) {
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
	if err := s.Guard().AppendManifest(ctx, &TrustManifest{Seq: 1, Type: "policy", ScopeID: "ac", Epoch: 1, Digest: "p1", Manifest: []byte(`{"p":1}`), TargetDescriptor: "d1"}, nil); err != nil {
		t.Fatal(err)
	}
	return v, s.Guard(), "ac"
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
		return &Lease{RequestID: id, AccountID: acct, BrokerID: "b", SecretVersion: 1, State: state, PolicyDigest: "p1", TargetDescriptorDigest: "d1", OpenedAt: now, ExpiresAt: now.Add(time.Hour)}
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

// §3.3 (security review of #16): a new lease must be under the current policy, and a policy
// that changes the descriptor is refused while a lease is open; the same target is not.
func TestDescriptorChangeWaitsForTheLease(t *testing.T) {
	v, g, acct := vaultAccountGuard(t)
	ctx := context.Background()
	now := time.Now().UTC()
	lease := &Lease{RequestID: "r1", AccountID: acct, BrokerID: "b", SecretVersion: 1, State: "active", PolicyDigest: "p0", TargetDescriptorDigest: "d1", OpenedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := v.MirrorLease(ctx, lease); !errors.Is(err, ErrPolicyChanged) {
		t.Fatalf("lease under a stale policy: %v", err)
	}
	lease.PolicyDigest = "p1"
	if err := v.MirrorLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	policy := func(seq int64, digest, target string) error {
		return g.AppendManifest(ctx, &TrustManifest{Seq: seq, Type: "policy", ScopeID: acct, Epoch: uint64(seq), Digest: digest, Manifest: []byte(`{}`), TargetDescriptor: target}, nil)
	}
	if err := policy(2, "p2", "d2"); !errors.Is(err, ErrLeaseOpen) {
		t.Fatalf("descriptor change during the lease: %v", err)
	}
	if err := policy(2, "p2", "d1"); err != nil {
		t.Fatalf("same target: %v", err)
	}
	lease.State = "closed"
	if err := v.MirrorLease(ctx, lease); err != nil {
		t.Fatal(err)
	}
	if err := policy(3, "p3", "d2"); err != nil {
		t.Fatalf("after the lease: %v", err)
	}
}

// enrollingAccount is a quarantined account whose stuck rotation "rot" is displaced by the
// reservation "enr", which expires at the returned deadline.
func enrollingAccount(t *testing.T, v VaultStore, acct string) time.Time {
	t.Helper()
	ctx := context.Background()
	if err := v.CreateAccount(ctx, &Account{ID: acct, AssetID: "as", Name: acct, AccountKind: "managed"}); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Reserve(ctx, acct, "rot", 0); err != nil {
		t.Fatal(err)
	}
	if err := v.SetHealth(ctx, acct, "quarantined", ""); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := v.ReserveEnrollment(ctx, acct, "enr", 0, now, time.Minute); err != nil {
		t.Fatal(err)
	}
	return now.Add(time.Minute)
}

// acceptedKeepsTheLock fails when an accepted enrollment no longer holds the account's lock.
func acceptedKeepsTheLock(t *testing.T, v VaultStore, acct string) {
	t.Helper()
	ctx := context.Background()
	st, err := v.EnrollmentState(ctx, acct, "enr")
	op, _, _ := v.Lock(ctx, acct)
	if err != nil || st != "accepted" || op != "enr" {
		t.Fatalf("%s: accepted, then state %q (%v) and lock %q", acct, st, err, op)
	}
}

// An acceptance that started before the deadline and commits while expiry is between
// finding the reservation and restoring the displaced lock keeps the lock (PR #15 review).
// The acceptance is held open on the row so expiry runs into it deterministically.
func TestExpiryNeverReleasesAnAcceptanceItRaces(t *testing.T) {
	s, _ := guardStoreFor(t)
	if s.driver != "postgres" {
		t.Skip("SQLite has one writer connection; needs KY_TEST_POSTGRES_DSN")
	}
	v := s.Vault()
	ctx := context.Background()
	if err := v.CreateAsset(ctx, &Asset{ID: "as", Name: "host"}); err != nil {
		t.Fatal(err)
	}
	deadline := enrollingAccount(t, v, "ac")
	accept, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer accept.Rollback()
	if _, err := accept.ExecContext(ctx, `UPDATE rotation_locks SET state = 'accepted' WHERE account_id = 'ac' AND operation_id = 'enr' AND state = 'reserved'`); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := v.ExpireEnrollments(ctx, deadline.Add(time.Second)); done <- err }()
	for start := time.Now(); ; time.Sleep(5 * time.Millisecond) {
		var waiting int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM pg_locks WHERE NOT granted`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting > 0 {
			break
		}
		if time.Since(start) > 10*time.Second {
			t.Fatal("expiry never waited on the acceptance")
		}
	}
	if err := accept.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	acceptedKeepsTheLock(t, v, "ac")
}

// Acceptance just before the deadline races expiry just after it, many times: an
// acceptance that succeeded always keeps the lock (PR #15 review).
func TestAcceptRacingExpiry(t *testing.T) {
	s, _ := guardStoreFor(t)
	v := s.Vault()
	ctx := context.Background()
	if err := v.CreateAsset(ctx, &Asset{ID: "as", Name: "host"}); err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for i := range 200 {
		acct := fmt.Sprintf("ac%d", i)
		deadline := enrollingAccount(t, v, acct)
		var wg sync.WaitGroup
		var aerr, eerr error
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			aerr = v.AcceptEnrollment(ctx, acct, "enr", deadline.Add(-time.Second))
		}()
		go func() { defer wg.Done(); <-start; _, eerr = v.ExpireEnrollments(ctx, deadline.Add(time.Second)) }()
		close(start)
		wg.Wait()
		if eerr != nil {
			t.Fatal(eerr)
		}
		if aerr == nil {
			accepted++
			acceptedKeepsTheLock(t, v, acct)
		} else if !errors.Is(aerr, ErrConflict) {
			t.Fatal(aerr)
		}
	}
	t.Logf("%d of 200 acceptances won the race", accepted)
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
		if err := v.Complete(ctx, op, acct, rs, current, "", LockDelete); err != nil {
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
		if err := v.Complete(ctx, op, acct, rs, id, "release_authorized", LockDelete); err != nil {
			t.Fatal(err)
		}
		return rs
	}
	old := release("op1", "e1")
	release("op2", "e2")
	if err := v.Complete(ctx, "op1", acct, old, "e1", "target_verified", LockDelete); err != nil {
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
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r(1, zeroHash, MaxChain/4)}, "", "", LockKeep); err != nil {
		t.Fatal(err)
	}
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{r(2, "h1", MaxChain/4+1)}, "", "", LockKeep); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("receipt over the chain cap: %v", err)
	}
}

// Queued pushes are taken once, oldest first, per broker, and expire (PR Reviewer Guide on
// #15).
func TestQueuedPushesAreTakenOnce(t *testing.T) {
	v, _ := vaultAccount(t)
	ctx := context.Background()
	now := time.Now()
	for i, p := range []*Push{{BrokerID: "b1", Type: "a"}, {BrokerID: "b2", Type: "x"}, {BrokerID: "b1", Type: "b"}, {BrokerID: "b1", Type: "old"}} {
		p.Body, p.ExpiresAt = []byte(fmt.Sprint(i)), now.Add(time.Minute)
		if p.Type == "old" {
			p.ExpiresAt = now.Add(-time.Second)
		}
		if err := v.QueuePush(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	ps, err := v.TakePushes(ctx, "b1", 10, now)
	if err != nil || len(ps) != 2 || ps[0].Type != "a" || ps[1].Type != "b" || string(ps[1].Body) != "2" {
		t.Fatalf("take: %+v %v", ps, err)
	}
	if ps, _ := v.TakePushes(ctx, "b1", 10, now); len(ps) != 0 {
		t.Fatalf("taken twice: %+v", ps)
	}
	if ps, _ := v.TakePushes(ctx, "b2", 10, now); len(ps) != 1 {
		t.Fatalf("other broker: %+v", ps)
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
	if err := v.Complete(ctx, "op", acct, []*StoredReceipt{abort}, "", "aborted", LockDelete); err != nil {
		t.Fatalf("terminal receipt after the largest envelope: %v", err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "" {
		t.Fatalf("lock still held by %s", op)
	}
}

// Identical transaction submissions racing each other all succeed; another transaction
// under the same request ID is a conflict (Guide on #15, "Concurrent retries"; the race
// needs PostgreSQL).
func TestConcurrentIdenticalTxSubmissionsSucceed(t *testing.T) {
	v, a := vaultAccount(t)
	ctx := context.Background()
	for round := range 20 {
		id := fmt.Sprintf("req-%d", round)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 16)
		for i := range errs {
			wg.Go(func() {
				<-start
				errs[i] = v.PutTx(ctx, id, a, "enroll", "d-"+id, []byte(id))
			})
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d, submission %d: %v", round, i, err)
			}
		}
	}
	if err := v.PutTx(ctx, "req-0", a, "enroll", "d-other", []byte("other")); !errors.Is(err, ErrConflict) {
		t.Fatalf("another transaction under the same request ID: %v", err)
	}
}

// Identical descriptor stores racing each other are all no-ops (Guide on #10, "Concurrent
// retries"; the race needs PostgreSQL).
func TestConcurrentIdenticalDescriptorStoresSucceed(t *testing.T) {
	v, a := vaultAccount(t)
	ctx := context.Background()
	for round := range 20 {
		dg := strings.Repeat(string(rune('a'+round)), 64)
		start := make(chan struct{})
		var wg sync.WaitGroup
		errs := make([]error, 16)
		for i := range errs {
			wg.Go(func() {
				<-start
				errs[i] = v.PutTargetDescriptor(ctx, dg, a, []byte(dg))
			})
		}
		close(start)
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Fatalf("round %d, store %d: %v", round, i, err)
			}
		}
	}
}

// A new challenge clears an earlier result: a checkout refused while another lease was open
// and then retried does not still read as refused (PR Reviewer Guide "Stale refusal" on #16).
func TestANewChallengeClearsTheEarlierResult(t *testing.T) {
	v, a := vaultAccount(t)
	ctx := context.Background()
	if err := v.PutTx(ctx, "req", a, "vault_checkout", "d-req", []byte("tx")); err != nil {
		t.Fatal(err)
	}
	if err := v.SetTxMailbox(ctx, "req", &TxMail{Result: "lease_open"}); err != nil {
		t.Fatal(err)
	}
	if err := v.SetTxMailbox(ctx, "req", &TxMail{Challenge: "c2", Purpose: "deliver"}); err != nil {
		t.Fatal(err)
	}
	mb, err := v.TxMailbox(ctx, "req")
	if err != nil || mb.Challenge != "c2" || mb.Result != "" {
		t.Fatalf("mailbox %+v %v", mb, err)
	}
	if err := v.SetTxMailbox(ctx, "req", &TxMail{Delivery: "w", Result: "ok"}); err != nil {
		t.Fatal(err)
	}
	if mb, _ := v.TxMailbox(ctx, "req"); mb.Result != "ok" || mb.Challenge != "c2" {
		t.Fatalf("after delivery %+v", mb)

// A retry of a completed enrollment's reservation takes no new version and no lock (PR
// Reviewer Guide "Retry Idempotency" on #15).
func TestACompletedEnrollmentIsNotReservedAgain(t *testing.T) {
	v, acct := vaultAccount(t)
	ctx := context.Background()
	now := time.Now().UTC()
	ver, err := v.ReserveEnrollment(ctx, acct, "enr", 0, now, 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.AcceptEnrollment(ctx, acct, "enr", now); err != nil {
		t.Fatal(err)
	}
	if err := v.PutEnvelope(ctx, "enr", &StoredEnvelope{EnvelopeID: "e1", AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "de1", Envelope: []byte("e1")}); err != nil {
		t.Fatal(err)
	}
	rs := []*StoredReceipt{{EnvelopeID: "e1", ReceiptSeq: 1, ReceiptType: "release", OperationID: "enr", Digest: "he1", PrevReceiptHash: zeroHash, Receipt: []byte("re1")}}
	if err := v.Complete(ctx, "enr", acct, rs, "e1", "", LockDelete); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReserveEnrollment(ctx, acct, "enr", 0, now, 15*time.Minute); !errors.Is(err, ErrConflict) {
		t.Fatalf("retry of a completed enrollment: %v", err)
	}
	if op, _, _ := v.Lock(ctx, acct); op != "" {
		t.Fatalf("lock %q after the refused retry", op)
	}
	if a, _ := v.GetAccount(ctx, acct); a.HighestSecretVersion != ver {
		t.Fatalf("highest version %d, want %d", a.HighestSecretVersion, ver)
	}
}
