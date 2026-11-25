package broker_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/cli"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
)

// checkoutRig: an ephemeral policy, alice may check out (no approvals), bob is enrolled
// too but not allowed.
type checkoutRig struct {
	*rig
	alice, bob *pqtest.Principal
	m          *broker.Machine
	now        time.Time
}

func newCheckoutRig(t *testing.T, edit ...func(*pqcrypto.PolicyManifest)) *checkoutRig {
	t.Helper()
	alice, bob := pqtest.NewPrincipal(t), pqtest.NewPrincipal(t)
	edits := append([]func(*pqcrypto.PolicyManifest){func(p *pqcrypto.PolicyManifest) {
		p.AllowedUserPrincipalIDs = []pqcrypto.UUID{alice.ID}
		p.EnrollerPrincipalIDs = []pqcrypto.UUID{alice.ID}
	}}, edit...)
	r := newRig(t, edits...)
	r.cp.Submit(r.cp.Dep.Enrollment(t, alice, 1))
	r.cp.Submit(r.cp.Dep.Enrollment(t, bob, 1))
	c := &checkoutRig{rig: r, alice: alice, bob: bob, now: time.Now().UTC()}
	c.m = r.machine()
	c.m.Now = func() time.Time { return c.now }
	t.Cleanup(func() { c.m.J.Close() })
	if err := c.m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c
}

func (c *checkoutRig) trust() *pqcrypto.Trust {
	c.T.Helper()
	tr := c.cp.Dep.Trust(c.T)
	ms, _ := c.cp.Store.Guard().Manifests(context.Background(), 0)
	for _, m := range ms {
		if _, err := tr.Accept(m.Manifest); err != nil {
			c.T.Fatal(err)
		}
	}
	return tr
}

// tx signs an action as who and stores it on the Control Plane, as the submit route does.
func (c *checkoutRig) tx(who *pqtest.Principal, a pqcrypto.Action) *cli.Checkout {
	c.T.Helper()
	a.AccountID = c.pol.AccountID
	co, err := cli.NewTransaction(c.trust(), a, who.ID, who.Sig, c.now)
	if err != nil {
		c.T.Fatal(err)
	}
	if err := c.cp.Store.Vault().PutTx(context.Background(), string(co.RequestID), string(c.pol.AccountID), a.ActionType, "d-"+string(co.RequestID), co.Tx); err != nil {
		c.T.Fatal(err)
	}
	return co
}

func (c *checkoutRig) checkoutTx(ttl int64) *cli.Checkout {
	return c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionVaultCheckout, SecretVersion: c.account(c.m).HighestCopied(),
		EncKeyID: pqcrypto.HexID(c.alice.Enc.Public().ID()), CheckoutTTLSeconds: ttl})
}

// challenge reads the challenge the broker posted for the CLI.
func (c *checkoutRig) challenge(id pqcrypto.UUID) []byte {
	c.T.Helper()
	mb, err := c.cp.Store.Vault().TxMailbox(context.Background(), string(id))
	if err != nil {
		c.T.Fatal(err)
	}
	b, err := pqcrypto.DecodeB64(mb.Challenge)
	if err != nil {
		c.T.Fatal(err)
	}
	return b
}

func (c *checkoutRig) delivery(id pqcrypto.UUID) (*pqcrypto.Recipient, string) {
	c.T.Helper()
	mb, _ := c.cp.Store.Vault().TxMailbox(context.Background(), string(id))
	if mb.Delivery == "" {
		return nil, mb.Result
	}
	var w pqcrypto.Recipient
	if err := json.Unmarshal([]byte(mb.Delivery), &w); err != nil {
		c.T.Fatal(err)
	}
	return &w, mb.Result
}

// open runs a checkout to delivery and returns the transaction.
func (c *checkoutRig) open(ttl int64) *cli.Checkout {
	c.T.Helper()
	co := c.checkoutTx(ttl)
	ctx := context.Background()
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		c.T.Fatal(err)
	}
	pop, err := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err != nil {
		c.T.Fatal(err)
	}
	if err := c.m.Proof(ctx, co.RequestID, pop); err != nil {
		c.T.Fatal(err)
	}
	return co
}

func (c *checkoutRig) currentEnvelope() []byte {
	a := c.account(c.m)
	return a.Chains[len(a.Chains)-1].Envelope
}

// §13 1A acceptance test 10: a checkout delivers a wrap that only enc_key_id opens.
func TestCheckoutDeliversAWrapOnlyTheRequesterOpens(t *testing.T) {
	c := newCheckoutRig(t)
	co := c.open(600)
	w, res := c.delivery(co.RequestID)
	if w == nil || res != "ok" {
		t.Fatalf("no delivery: %s", res)
	}
	pw, err := cli.OpenDelivery(c.trust(), c.currentEnvelope(), *w, c.alice.Enc)
	if err != nil || string(pw) != initialPassword {
		t.Fatalf("open: %q %v", pw, err)
	}
	if _, err := cli.OpenDelivery(c.trust(), c.currentEnvelope(), *w, c.bob.Enc); err == nil {
		t.Fatal("another key opened the wrap")
	}
	if l, err := c.cp.Store.Vault().GetLease(context.Background(), string(co.RequestID)); err != nil || l.State != broker.LeaseActive {
		t.Fatalf("control plane lease %+v %v", l, err)
	}
	if n := c.target.logins[initialPassword]; n != 1 {
		t.Fatalf("%d verifications at delivery", n)
	}
}

// §13 1A acceptance test 10: a possession proof over another transaction's digest opens no
// lease and burns nothing.
func TestProofOverAnotherTransactionOpensNothing(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	co := c.checkoutTx(600)
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		t.Fatal(err)
	}
	other := c.checkoutTx(600)
	other.Cnf = co.Cnf // even signed with the right cnf key
	bad, _ := other.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err := c.m.Proof(ctx, co.RequestID, bad); !errors.Is(err, pqcrypto.ErrStale) {
		t.Fatalf("got %v", err)
	}
	if a := c.account(c.m); a.Lease != nil || c.m.J.Burned(co.RequestID) {
		t.Fatalf("lease %+v burned %v", a.Lease, c.m.J.Burned(co.RequestID))
	}
	good, _ := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err := c.m.Proof(ctx, co.RequestID, good); err != nil {
		t.Fatalf("the right proof after a bad one: %v", err)
	}
	if err := c.m.Proof(ctx, co.RequestID, good); !errors.Is(err, broker.ErrNoChallenge) {
		t.Fatalf("challenge reused: %v", err)
	}
}

// §13 1A acceptance test 10: a credential that no longer verifies at delivery delivers
// nothing and quarantines the account.
func TestStaleCredentialAtDeliveryQuarantines(t *testing.T) {
	c := newCheckoutRig(t)
	c.target.password = "changed-out-of-band"
	co := c.open(600)
	w, res := c.delivery(co.RequestID)
	a := c.account(c.m)
	if w != nil || res != broker.HealthAuthFailed || !a.Quarantined || a.Lease.State != broker.LeaseClosed {
		t.Fatalf("delivery=%v result=%s quarantined=%v lease=%+v", w, res, a.Quarantined, a.Lease)
	}
}

// §13 1A acceptance test 10: a second checkout during the lease is refused; a scheduled
// occurrence during the lease is deferred.
func TestLeaseBlocksSecondCheckoutAndDefersTheSchedule(t *testing.T) {
	c := newCheckoutRig(t, scheduled(time.Now().UTC()), func(p *pqcrypto.PolicyManifest) { p.MaxCheckoutTTLSeconds = 3 * 86400 })
	c.open(3 * 86400)
	if err := c.m.Tx(context.Background(), c.checkoutTx(600).Tx); !errors.Is(err, broker.ErrLeaseOpen) {
		t.Fatalf("second checkout: %v", err)
	}
	c.now = c.now.Add(day + time.Hour) // an occurrence is due
	if err := c.m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, writes := c.target.state(); writes != 0 || c.account(c.m).Run != nil {
		t.Fatal("a scheduled rotation ran during the lease")
	}
}

// §13 1A acceptance test 10: check-in with a different key is refused; with the same key it
// triggers the cleanup rotation, which closes the lease.
func TestCheckinTriggersTheCleanupRotation(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	co := c.open(3600)
	if err := c.m.Checkin(ctx, co.RequestID); err != nil {
		t.Fatal(err)
	}
	ch := c.challenge(co.RequestID)
	stranger := *co
	stranger.Cnf, _ = pqcrypto.GenerateSigningKey()
	bad, _ := stranger.Proof(ch, pqcrypto.PurposeCheckin)
	if err := c.m.Proof(ctx, co.RequestID, bad); err == nil {
		t.Fatal("check-in with another key accepted")
	}
	good, _ := co.Proof(ch, pqcrypto.PurposeCheckin)
	if err := c.m.Proof(ctx, co.RequestID, good); err != nil {
		t.Fatal(err)
	}
	if l := c.account(c.m).Lease; l.State != broker.LeaseRotationPending {
		t.Fatalf("lease %s", l.State)
	}
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	if pw, writes := c.target.state(); writes != 1 || pw == initialPassword || a.Lease.State != broker.LeaseClosed || a.Lease.CloseReason != "closed_by_release" {
		t.Fatalf("writes=%d lease=%+v", writes, a.Lease)
	}
	want, _ := pqcrypto.RequestOpID(co.RequestID, 0)
	if a.Run.OperationID != want {
		t.Fatalf("cleanup op %s, want opid(request_id, 0) %s", a.Run.OperationID, want)
	}
	if l, _ := c.cp.Store.Vault().GetLease(ctx, string(co.RequestID)); l.State != broker.LeaseClosed {
		t.Fatalf("control plane lease %s", l.State)
	}
}

// §13 1A acceptance test 10: expiry after the transaction expired triggers a cleanup
// rotation that survives a broker restart and closes the lease.
func TestExpiryCleanupSurvivesARestart(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.open(60)
	c.now = c.now.Add(time.Hour) // the lease and the transaction have both expired
	c.m.Hook = func(p string) error {
		if p == "after_write" {
			return errors.New("kill")
		}
		return nil
	}
	if err := c.m.Tick(ctx); !errors.Is(err, broker.ErrStopped) {
		t.Fatalf("tick: %v", err)
	}
	c.m.J.Close()
	c.m = c.machine()
	c.m.Now = func() time.Time { return c.now }
	if err := c.m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	if _, writes := c.target.state(); writes != 1 || a.Lease.State != broker.LeaseClosed {
		t.Fatalf("writes=%d lease=%+v", writes, a.Lease)
	}
}

// §13 1A acceptance test 9: a lease cleanup refused for minimum age retries at
// max(last change + min age, now + 1 h), never stops after three refusals, and a
// manual_rotation re-arms it under the same lease.
func TestRefusedCleanupRetriesAndManualRotationRearms(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	co := c.open(60)
	c.target.refuseAfterCommit = true
	c.now = c.now.Add(time.Hour)
	for i := range broker.MaxRefusals + 1 {
		if err := c.m.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		l := c.account(c.m).Lease
		if l.State != broker.LeaseRotationPending || l.Attempt != pqcrypto.Counter(i+1) || !l.NextAttemptAt.Equal(c.now.Add(time.Hour)) {
			t.Fatalf("refusal %d: %+v", i, l)
		}
		c.now = c.now.Add(time.Hour)
	}
	// Not yet due: nothing runs; a manual_rotation re-arms the same lease now.
	c.now = c.now.Add(-30 * time.Minute)
	mr := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation})
	if err := c.m.Tx(ctx, mr.Tx); err != nil {
		t.Fatal(err)
	}
	if l := c.account(c.m).Lease; !l.NextAttemptAt.Equal(c.now) || l.RequestID != co.RequestID {
		t.Fatalf("not re-armed: %+v", l)
	}
	c.target.refuseAfterCommit = false
	c.m.Tick(ctx)
	if l := c.account(c.m).Lease; l.State != broker.LeaseClosed {
		t.Fatalf("lease %+v", l)
	}
}

// §3.4: manual_rotation runs a rotation under opid(request_id, 0) and is refused during an
// active lease; its request ID cannot be replayed.
func TestManualRotation(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	mr := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation})
	if err := c.m.Tx(ctx, mr.Tx); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	want, _ := pqcrypto.RequestOpID(mr.RequestID, 0)
	if a.Run.State != broker.StateReleaseAuthorized || a.Run.OperationID != want {
		t.Fatalf("run %+v", a.Run)
	}
	if err := c.m.Tx(ctx, mr.Tx); !errors.Is(err, pqcrypto.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	c.open(600)
	if err := c.m.Tx(ctx, c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation}).Tx); !errors.Is(err, broker.ErrLeaseOpen) {
		t.Fatalf("during an active lease: %v", err)
	}
}

// §3.6 step 3: the broker re-checks at proof time; a lease opened after this request's
// challenge refuses it.
func TestProofRechecksForAnOpenLease(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	first := c.checkoutTx(600)
	if err := c.m.Tx(ctx, first.Tx); err != nil {
		t.Fatal(err)
	}
	pop, _ := first.Proof(c.challenge(first.RequestID), pqcrypto.PurposeDeliver)
	c.open(600) // a second checkout completes in between
	if err := c.m.Proof(ctx, first.RequestID, pop); !errors.Is(err, broker.ErrLeaseOpen) {
		t.Fatalf("got %v", err)
	}
}
