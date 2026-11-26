package broker_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/broker/brokerrig"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/cli"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
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
// replaces that refusal with "ok" and triggers the cleanup rotation, which closes the lease.
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
	// The refusal is published before Proof returns, under the same mutex hold, so a later
	// accepted proof always supersedes it (PR Reviewer Guide "Stale refusal" on #16).
	if _, res := c.delivery(co.RequestID); res == "" || res == "ok" {
		t.Fatalf("result after the refused check-in %q", res)
	}
	good, _ := co.Proof(ch, pqcrypto.PurposeCheckin)
	if err := c.m.Proof(ctx, co.RequestID, good); err != nil {
		t.Fatal(err)
	}
	// The accepted check-in replaces the earlier refusal (PR Reviewer Guide "Stale refusal").
	if _, res := c.delivery(co.RequestID); res != "ok" {
		t.Fatalf("result after the accepted check-in %q", res)
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
	if _, res := c.delivery(mr.RequestID); res != "ok" {
		t.Fatalf("re-arm result %q", res)
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
	// The CLI following the mailbox sees the rotation finish (Guide on #16).
	if _, res := c.delivery(mr.RequestID); res != "ok" {
		t.Fatalf("result %q", res)
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

// §3.3 (security review of #16): after a descriptor change, checkout is refused before any
// login or delivery, at the transaction and again at the proof.
func TestCheckoutAcrossADescriptorChangeIsRefused(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	early := c.checkoutTx(600)
	if err := c.m.Tx(ctx, early.Tx); err != nil {
		t.Fatal(err)
	}
	pop, _ := early.Proof(c.challenge(early.RequestID), pqcrypto.PurposeDeliver)
	moveTarget(t, c.rig)
	if err := c.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// A transaction signed under the old policy is stale now.
	if err := c.m.Proof(ctx, early.RequestID, pop); !errors.Is(err, pqcrypto.ErrStale) {
		t.Fatalf("proof after the change: %v", err)
	}
	late := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionVaultCheckout, SecretVersion: c.account(c.m).HighestCopied(),
		EncKeyID: pqcrypto.HexID(c.alice.Enc.Public().ID()), CheckoutTTLSeconds: 600})
	if err := c.m.Tx(ctx, late.Tx); !errors.Is(err, broker.ErrNeedsEnrollment) {
		t.Fatalf("checkout after the change: %v", err)
	}
	if len(c.target.hosts) != 0 || c.account(c.m).Lease != nil || c.account(c.m).Health != broker.HealthNeedsEnrollment {
		t.Fatalf("hosts=%v lease=%+v", c.target.hosts, c.account(c.m).Lease)
	}
	if w, _ := c.delivery(early.RequestID); w != nil {
		t.Fatal("delivered")
	}
}

// wrapCP routes c.m through a WrapCP so a test can fail single Control Plane calls.
func (c *checkoutRig) wrapCP() *brokerrig.WrapCP {
	w := &brokerrig.WrapCP{ControlPlane: c.m.CP}
	c.m.CP = w
	return w
}

// p2 signs policy epoch 2 for a new SSH descriptor at db2.example.test.
func (c *checkoutRig) p2() []byte {
	raw, dg := c.cp.Dep.SSHTarget(c.T, c.pol.AccountID, pqtest.UUID(), "db2.example.test", 22, "svc", pqcrypto.HexID(strings.Repeat("cd", 32)))
	if err := c.cp.Store.Vault().PutTargetDescriptor(context.Background(), string(dg), string(c.pol.AccountID), raw); err != nil {
		c.T.Fatal(err)
	}
	p := *c.pol
	p.Signatures, p.Epoch, p.TargetDescriptorDigest = nil, 2, dg
	return c.cp.Dep.Signed(c.T, &p)
}

// §3.3 (security review of #16): a descriptor change that reaches the broker during a lease
// is deferred; after expiry and a restart the cleanup rotates the original target, which
// invalidates the checked-out credential, and only then is the new policy applied.
func TestLeaseCleanupStaysAtItsTargetAcrossADescriptorChange(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.open(60)
	// The Control Plane relays a signed descriptor change during the lease (it refuses to
	// accept one itself; the broker must not rely on that).
	p2 := c.p2()
	w := c.wrapCP()
	w.OnSync = func(ctx context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error) {
		r, err := w.ControlPlane.Sync(ctx, req)
		if err == nil && len(r.Manifests) > 0 {
			r.Manifests = append(r.Manifests, p2)
		}
		return r, err
	}
	if err := c.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := c.m.Trust.Policy(c.pol.AccountID); p.Epoch != 1 || len(c.account(c.m).DeferredPolicy) == 0 {
		t.Fatalf("policy epoch %s applied during the lease", p.Epoch)
	}
	c.now = c.now.Add(time.Hour) // the lease expires
	c.m.J.Close()
	c.m = c.machine()
	c.m.Now = func() time.Time { return c.now }
	if err := c.m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	if pw, writes := c.target.state(); writes != 1 || pw == initialPassword || a.Lease.State != broker.LeaseClosed || a.Lease.CloseReason != "closed_by_release" {
		t.Fatalf("writes=%d lease=%+v", writes, a.Lease)
	}
	if slices.Contains(c.target.hosts, "db2.example.test") {
		t.Fatalf("cleanup went to the new target: %v", c.target.hosts)
	}
	if p, _ := c.m.Trust.Policy(c.pol.AccountID); p.Epoch != 2 || a.DeferredPolicy != nil {
		t.Fatalf("deferred policy not applied after the lease closed: epoch %s", p.Epoch)
	}
}

// §3.3: the Control Plane refuses a descriptor change while it holds an open lease, so it
// never reports the new target as current; the same policy is accepted after cleanup.
func TestControlPlaneRefusesADescriptorChangeDuringALease(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.open(60)
	p2 := c.p2()
	if _, _, err := c.cp.L.Trust.Submit(ctx, p2, "custodian", ""); !errors.Is(err, store.ErrLeaseOpen) {
		t.Fatalf("submit during the lease: %v", err)
	}
	c.cp.L.Trust.View(ctx, func(tr *pqcrypto.Trust) error {
		if p, _ := tr.Policy(c.pol.AccountID); p.Epoch != 1 {
			t.Errorf("control plane policy epoch %s", p.Epoch)
		}
		return nil
	})
	c.now = c.now.Add(time.Hour)
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	c.cp.Submit(p2)
}

// §3.3: a lease opened under a policy the Control Plane has since replaced is not mirrored,
// so the broker closes it before it unwraps, logs in or delivers anything.
func TestLeaseUnderAReplacedPolicyDeliversNothing(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	co := c.checkoutTx(600)
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		t.Fatal(err)
	}
	pop, _ := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	c.cp.Submit(c.p2()) // accepted at the Control Plane; the broker has not synced it yet
	if err := c.m.Proof(ctx, co.RequestID, pop); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	if w, res := c.delivery(co.RequestID); w != nil || res != "not_mirrored" || len(c.target.hosts) != 0 || a.Lease.State != broker.LeaseClosed {
		t.Fatalf("delivered=%v result=%q hosts=%v lease=%+v", w != nil, res, c.target.hosts, a.Lease)
	}
}

// Guide on #16 (lost delivery): a delivery the Control Plane did not acknowledge is
// journaled and re-sent by the next tick, without a second login. Until then it is pending,
// not refused: the proof succeeds and no result is published ("Premature refusal").
func TestLostDeliveryIsResent(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	w := c.wrapCP()
	w.DeliveryErr = errors.New("connection lost")
	co := c.checkoutTx(600)
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		t.Fatal(err)
	}
	pop, _ := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err := c.m.Proof(ctx, co.RequestID, pop); err != nil {
		t.Fatalf("a pending delivery was refused: %v", err)
	}
	if d, res := c.delivery(co.RequestID); d != nil || res != "" {
		t.Fatalf("delivered=%v result=%q", d != nil, res)
	}
	logins := len(c.target.hosts)
	w.DeliveryErr = nil
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if d, _ := c.delivery(co.RequestID); d == nil || c.account(c.m).Lease.Delivery != nil || len(c.target.hosts) != logins {
		t.Fatalf("delivered=%v hosts=%v", d != nil, c.target.hosts)
	}
}

// Guide on #16 (lost mirror): a new checkout never replaces a lease whose closure the
// Control Plane has not acknowledged; it sends the closure first.
func TestUnmirroredClosureBlocksTheNextCheckout(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	first := c.open(60)
	w := c.wrapCP()
	w.LeaseErr = errors.New("connection lost")
	c.now = c.now.Add(time.Hour)
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if l := c.account(c.m).Lease; l.State != broker.LeaseClosed || l.Mirrored {
		t.Fatalf("lease %+v", l)
	}
	if err := c.m.Tx(ctx, c.checkoutTx(600).Tx); !errors.Is(err, broker.ErrLeaseOpen) {
		t.Fatalf("checkout over an unmirrored closure: %v", err)
	}
	w.LeaseErr = nil
	c.open(600)
	if l, _ := c.cp.Store.Vault().GetLease(ctx, string(first.RequestID)); l.State != broker.LeaseClosed {
		t.Fatalf("control plane kept the first lease %s", l.State)
	}
}

// §3.3: cleanup refuses a policy that pins another descriptor than its lease's.
func TestCleanupIsBoundToItsDescriptor(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.open(60)
	a := c.account(c.m)
	a.Lease.TargetDescriptorDigest = pqcrypto.HexID(strings.Repeat("ef", 32))
	if err := c.m.J.Save(a); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(time.Hour)
	c.m.Tick(ctx)
	if _, writes := c.target.state(); writes != 0 || c.account(c.m).Lease.State == broker.LeaseClosed {
		t.Fatal("cleanup rotated under another descriptor")
	}
}

// A cleanup whose receipts the Control Plane did not acknowledge is re-sent on the next
// tick, not left open until a reconnect: the lease closes, with one write (PR Reviewer
// Guide on #16).
func TestUnacknowledgedCleanupReceiptsResendOnTheNextTick(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.open(60)
	c.now = c.now.Add(time.Hour)
	w := &brokerrig.WrapCP{ControlPlane: c.m.CP, ReceiptsErr: errors.New("control plane unreachable")}
	c.m.CP = w
	if err := c.m.Tick(ctx); err == nil {
		t.Fatal("delivery did not fail")
	}
	if a := c.account(c.m); !a.Run.Open() || a.Run.Sent || a.Lease.State != broker.LeaseRotationPending {
		t.Fatalf("after the failed delivery: run %s sent=%v lease %s", a.Run.State, a.Run.Sent, a.Lease.State)
	}
	w.ReceiptsErr = nil
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	a := c.account(c.m)
	if _, writes := c.target.state(); writes != 1 || a.Run.State != broker.StateReleaseAuthorized || a.Lease.State != broker.LeaseClosed {
		t.Fatalf("writes=%d run %s lease %s", writes, a.Run.State, a.Lease.State)
	}
}

// failResults fails the next n result deliveries.
type failResults struct {
	broker.ControlPlane
	n int
}

func (f *failResults) TxResult(ctx context.Context, r brokerproto.TxResultRequest) error {
	if f.n > 0 {
		f.n--
		return errors.New("transient")
	}
	return f.ControlPlane.TxResult(ctx, r)
}

// A manual_rotation result that could not be delivered is journaled and re-sent by the
// next tick, and by recovery after a restart (Guide on #16, "Lost results").
func TestManualRotationResultIsResent(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	cp := c.m.CP
	c.m.CP = &failResults{ControlPlane: cp, n: 1}
	mr := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation})
	if err := c.m.Tx(ctx, mr.Tx); err != nil {
		t.Fatal(err)
	}
	if _, res := c.delivery(mr.RequestID); res != "" {
		t.Fatalf("result %q despite the failed delivery", res)
	}
	if a := c.account(c.m); len(a.Results) != 1 {
		t.Fatalf("%d results journaled", len(a.Results))
	}
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := c.delivery(mr.RequestID); res != "ok" {
		t.Fatalf("result after the tick %q", res)
	}
	if a := c.account(c.m); len(a.Results) != 0 || !a.Run.ResultQueued {
		t.Fatalf("results %+v queued=%v", a.Results, a.Run.ResultQueued)
	}
}

// A refusal at delivery whose result could not be sent is journaled with the lease's
// closure and re-sent by the next tick (Guide on #16, "Lost outcome").
func TestDeliveryRefusalResultIsResent(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	c.target.password = "changed-out-of-band"
	c.m.CP = &failResults{ControlPlane: c.m.CP, n: 1}
	co := c.open(600)
	if _, res := c.delivery(co.RequestID); res != "" {
		t.Fatalf("result %q despite the failed delivery", res)
	}
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := c.delivery(co.RequestID); res != broker.HealthAuthFailed {
		t.Fatalf("result after the tick %q", res)
	}
}

// A crash after the lease opened but before its wrap was journaled delivered nothing:
// recovery closes the lease and reports it, so the account is not blocked until expiry
// (Guide on #16, "Interrupted delivery").
func TestInterruptedDeliveryClosesTheLease(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	co := c.checkoutTx(600)
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		t.Fatal(err)
	}
	pop, err := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err != nil {
		t.Fatal(err)
	}
	c.m.Hook = func(p string) error {
		if p == "lease_open" {
			return errors.New("kill")
		}
		return nil
	}
	if err := c.m.Proof(ctx, co.RequestID, pop); !errors.Is(err, broker.ErrStopped) {
		t.Fatalf("proof: %v", err)
	}
	c.m.Hook = nil
	if err := c.m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if l := c.account(c.m).Lease; l.State != broker.LeaseClosed || l.CloseReason != "interrupted" {
		t.Fatalf("lease %+v", l)
	}
	if w, res := c.delivery(co.RequestID); w != nil || res != "interrupted" {
		t.Fatalf("delivery=%v result=%q", w, res)
	}
}

// A refusal whose result could not be sent is journaled and re-sent by the next tick and by
// recovery; one the Control Plane rejects is dropped, and a later message for the request
// supersedes it (Guide on #16, "Lost refusals").
func TestRefusalsAreJournaledUntilAcknowledged(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	cp := c.m.CP
	c.m.CP = &failResults{ControlPlane: cp, n: 1}
	co, other := c.checkoutTx(600), c.checkoutTx(600)
	c.m.Refused(ctx, co.RequestID, "lease_open")
	if _, res := c.delivery(co.RequestID); res != "" {
		t.Fatalf("result %q despite the failed delivery", res)
	}
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := c.delivery(co.RequestID); res != "lease_open" {
		t.Fatalf("result after the tick %q", res)
	}
	// Across a restart, behind a refusal the Control Plane rejects (no such request).
	c.m.CP = &failResults{ControlPlane: cp, n: 100} // until the restart
	stale := pqtest.UUID()
	for stale > other.RequestID { // sent first, so a rejection must not stop the rest
		stale = pqtest.UUID()
	}
	c.m.Refused(ctx, stale, "stale")
	c.m.Refused(ctx, other.RequestID, "blocked")
	c.m.Refused(ctx, co.RequestID, "superseded")
	c.m.Refused(ctx, co.RequestID, "")
	c.m.J.Close()
	c.m = c.machine()
	c.m.Now = func() time.Time { return c.now }
	if err := c.m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := c.delivery(other.RequestID); res != "blocked" {
		t.Fatalf("result after recovery %q", res)
	}
	if _, res := c.delivery(co.RequestID); res != "lease_open" {
		t.Fatalf("a superseded refusal was sent: %q", res)
	}
	if rs, _ := c.m.J.Refusals(); len(rs) != 0 {
		t.Fatalf("%d refusals left", len(rs))
	}
}

// A manual_rotation whose abort was not delivered is finished by a tick that then starts a
// due scheduled occurrence; the manual request still gets its result (PR Reviewer Guide
// "Lost result" on #16).
func TestRecoveredManualRotationKeepsItsResult(t *testing.T) {
	c := newCheckoutRig(t, scheduled(time.Now().UTC()))
	ctx := context.Background()
	down := errors.New("control plane unreachable")
	w := &brokerrig.WrapCP{ControlPlane: c.m.CP, ReceiptsErr: down, OnIntent: func(context.Context, []byte) error { return down }}
	c.m.CP = w
	mr := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation})
	c.m.Tx(ctx, mr.Tx)
	if a := c.account(c.m); a.Run.Request != mr.RequestID || a.Run.Sent {
		t.Fatalf("the manual run's results were delivered: %+v", a.Run)
	}
	w.ReceiptsErr, w.OnIntent = nil, nil
	c.now = c.now.Add(day + time.Hour) // a scheduled occurrence is due
	if err := c.m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if a := c.account(c.m); a.Run.Request == mr.RequestID {
		t.Fatal("no scheduled run replaced the manual one")
	}
	if _, res := c.delivery(mr.RequestID); res != broker.StateAborted {
		t.Fatalf("manual_rotation result %q", res)
	}
}

// A duplicate of a completed manual_rotation is refused as a replay without replacing the
// "ok" its requester already has (PR Reviewer Guide "Overwritten success" on #16).
func TestAReplayKeepsTheEarlierOutcome(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	mr := c.tx(c.alice, pqcrypto.Action{ActionType: pqcrypto.ActionManualRotation})
	if err := c.m.Tx(ctx, mr.Tx); err != nil {
		t.Fatal(err)
	}
	if err := c.m.Tx(ctx, mr.Tx); !errors.Is(err, pqcrypto.ErrReplay) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, res := c.delivery(mr.RequestID); res != "ok" {
		t.Fatalf("result after the replay %q", res)
	}
}

// A lease that expires with its wrap still undelivered tells the requester so, instead of
// leaving the mailbox at the challenge (PR Reviewer Guide "Missing outcome" on #16).
func TestAnUndeliveredWrapThatExpiresIsReported(t *testing.T) {
	c := newCheckoutRig(t)
	ctx := context.Background()
	w := c.wrapCP()
	w.DeliveryErr = errors.New("connection lost")
	co := c.checkoutTx(60)
	if err := c.m.Tx(ctx, co.Tx); err != nil {
		t.Fatal(err)
	}
	pop, _ := co.Proof(c.challenge(co.RequestID), pqcrypto.PurposeDeliver)
	if err := c.m.Proof(ctx, co.RequestID, pop); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(time.Hour)
	c.m.Tick(ctx) // expires the lease
	c.m.Tick(ctx) // drops the wrap
	if d, res := c.delivery(co.RequestID); d != nil || res != broker.ReasonLeaseExpired {
		t.Fatalf("delivered=%v result=%q", d != nil, res)
	}
	if c.account(c.m).Lease.Delivery != nil {
		t.Fatal("the wrap is still journaled")
	}
}
