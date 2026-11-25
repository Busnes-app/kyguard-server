package broker_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/cli"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// enrollRig is a rig whose policy names alice as the only enroller.
type enrollRig struct {
	*rig
	alice *pqtest.Principal
}

func newEnrollRig(t *testing.T, seed bool) *enrollRig {
	t.Helper()
	alice := pqtest.NewPrincipal(t)
	edit := func(p *pqcrypto.PolicyManifest) { p.EnrollerPrincipalIDs = []pqcrypto.UUID{alice.ID} }
	base := newRigWith(t, !seed, edit)
	base.cp.Submit(base.cp.Dep.Enrollment(t, alice, 1))
	m := base.machine()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	m.J.Close()
	return &enrollRig{rig: base, alice: alice}
}

// cliTrust is the CLI's own verified state: the pinned bundle and every manifest.
func (r *enrollRig) cliTrust() *pqcrypto.Trust {
	r.T.Helper()
	tr := r.cp.Dep.Trust(r.T)
	ms, err := r.cp.Store.Guard().Manifests(context.Background(), 0)
	if err != nil {
		r.T.Fatal(err)
	}
	for _, m := range ms {
		if _, err := tr.Accept(m.Manifest); err != nil {
			r.T.Fatal(err)
		}
	}
	return tr
}

// submit plays the CLI and the Control Plane up to the relay: reserve (with the given
// clock), seal and sign, store the candidate. It returns what the broker receives.
func (r *enrollRig) submit(who *pqtest.Principal, password string, now time.Time) (*cli.Enrollment, pqcrypto.UUID) {
	r.T.Helper()
	ctx := context.Background()
	reqID := pqtest.UUID()
	op, _ := pqcrypto.RequestOpID(reqID, 0)
	v, err := r.cp.Store.Vault().ReserveEnrollment(ctx, string(r.pol.AccountID), string(op), 0, now, 15*time.Minute)
	if err != nil {
		r.T.Fatal(err)
	}
	e, err := cli.SealEnrollment(r.cliTrust(), r.pol.AccountID, reqID, pqcrypto.Counter(v), who.ID, who.Sig, []byte(password), time.Now())
	if err != nil {
		r.T.Fatal(err)
	}
	var env pqcrypto.SecretEnvelope
	pqtest.Decode(r.T, e.Envelope, &env)
	d, _ := pqcrypto.ObjDigest(&env)
	if err := r.cp.Store.Vault().PutEnvelope(ctx, string(op), &store.StoredEnvelope{EnvelopeID: string(env.EnvelopeID), AccountID: string(r.pol.AccountID),
		SecretVersion: v, EnvelopeKind: "managed", Digest: string(d.Hex()), Envelope: e.Envelope}); err != nil {
		r.T.Fatal(err)
	}
	return e, op
}

func (r *enrollRig) enroll(m *broker.Machine, password string) (*cli.Enrollment, error) {
	e, _ := r.submit(r.alice, password, time.Now().UTC())
	return e, m.Enroll(context.Background(), e.Tx, e.Envelope)
}

func (r *enrollRig) current(m *broker.Machine) *pqcrypto.Chain {
	r.T.Helper()
	a := r.account(m)
	var chains []*pqcrypto.Chain
	for _, c := range a.Chains {
		v, err := m.Trust.VerifyEnvelope(c.Envelope, pqcrypto.EnvelopeContext{})
		if err != nil {
			r.T.Fatal(err)
		}
		ch := pqcrypto.NewChain(v)
		for _, rc := range c.Receipts {
			if _, err := m.Trust.Append(ch, rc, pqcrypto.ReceiptContext{}); err != nil {
				r.T.Fatal(err)
			}
		}
		chains = append(chains, ch)
	}
	return pqcrypto.CurrentEnvelopeOf(chains)
}

// §13 1A acceptance test 1: the correct credential yields vault_commit (a Yellow account).
func TestFirstEnrollment(t *testing.T) {
	r := newEnrollRig(t, false)
	m := r.machine()
	defer m.J.Close()
	if _, err := r.enroll(m, initialPassword); err != nil {
		t.Fatal(err)
	}
	cur := r.current(m)
	if cur == nil || !cur.VaultCommitted || cur.Released {
		t.Fatalf("current %+v", cur)
	}
	if ca := r.cpAccount(); ca.CurrentEnvelopeID != string(cur.Envelope.EnvelopeID) || r.cpLock() != "" {
		t.Fatalf("control plane current=%s lock=%s", ca.CurrentEnvelopeID, r.cpLock())
	}
	if n := r.target.logins[initialPassword]; n != 1 {
		t.Fatalf("%d binds", n)
	}
	// The enrolled envelope is the baseline for the next rotation.
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	if a := r.account(m); a.Run.State != broker.StateReleaseAuthorized {
		t.Fatalf("rotation after enrollment: %+v", a.Run)
	}
}

// §13 1A acceptance test 1: a wrong credential yields abort (enrollment_failed) with exactly
// one failed bind; a healthy account's current envelope is unchanged.
func TestEnrollmentWithAWrongCredential(t *testing.T) {
	r := newEnrollRig(t, true)
	m := r.machine()
	defer m.J.Close()
	before := r.cpAccount().CurrentEnvelopeID
	if _, err := r.enroll(m, "not-the-Passw0rd"); err != nil {
		t.Fatal(err)
	}
	a := r.account(m)
	if r.target.failed != 1 || a.Enrollment.Verified || a.Quarantined {
		t.Fatalf("failed binds %d, %+v", r.target.failed, a.Enrollment)
	}
	if ca := r.cpAccount(); ca.CurrentEnvelopeID != before || r.cpLock() != "" {
		t.Fatalf("control plane current=%s lock=%s", ca.CurrentEnvelopeID, r.cpLock())
	}
	if st, _ := r.cp.Store.Vault().EnrollmentState(context.Background(), string(r.pol.AccountID), string(a.Enrollment.OperationID)); st != "failed" {
		t.Fatalf("state %s", st)
	}
}

// §13 1A acceptance test 1: enroll from a principal outside enroller_principal_ids, or a
// replayed request_id, is refused before any bind.
func TestEnrollmentRefusedBeforeAnyBind(t *testing.T) {
	r := newEnrollRig(t, false)
	bob := pqtest.NewPrincipal(t)
	r.cp.Submit(r.cp.Dep.Enrollment(t, bob, 1))
	m := r.machine()
	defer m.J.Close()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The CLI refuses to sign for bob; a forged request signed by bob is refused by the broker.
	if _, err := cli.SealEnrollment(r.cliTrust(), r.pol.AccountID, pqtest.UUID(), 1, bob.ID, bob.Sig, []byte("x"), time.Now()); !errors.Is(err, cli.ErrNotEnroller) {
		t.Fatalf("cli: %v", err)
	}
	e, _ := r.submit(r.alice, initialPassword, time.Now().UTC())
	var tx pqcrypto.AccessTransaction
	pqtest.Decode(t, e.Tx, &tx)
	tx.RequesterPrincipalID, tx.Signatures = bob.ID, nil
	pqcrypto.Sign(&tx, pqcrypto.RoleUser, bob.Sig)
	if err := m.Enroll(context.Background(), pqtest.Canon(t, &tx), e.Envelope); !errors.Is(err, pqcrypto.ErrNotAllowed) {
		t.Fatalf("outside the enrollers: %v", err)
	}
	if len(r.target.logins) != 0 {
		t.Fatal("bound before refusing")
	}
	if err := m.Enroll(context.Background(), e.Tx, e.Envelope); err != nil {
		t.Fatal(err)
	}
	if err := m.Enroll(context.Background(), e.Tx, e.Envelope); !errors.Is(err, pqcrypto.ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	if n := r.target.logins[initialPassword]; n != 1 {
		t.Fatalf("%d binds", n)
	}
}

// quarantineV2 runs a rotation whose write is ambiguous and did not apply: v2 is stuck and
// the account is quarantined (§4.3).
func quarantineV2(t *testing.T, r *enrollRig, m *broker.Machine) {
	t.Helper()
	r.target.ambiguous = errors.New("connection reset")
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	r.target.ambiguous = nil
	if a := r.account(m); !a.Quarantined || a.Run.State != broker.StateWriteOutcomeUnknown {
		t.Fatalf("not stuck: %+v", a.Run)
	}
}

// §13 1A acceptance test 4: release at v1; v2 ambiguous and quarantined; the password is
// reset at the target; re-enrollment yields v3, current, with abort
// (superseded_by_reenrollment) on v2 and v1's receipts kept; the next rotation succeeds.
func TestReEnrollmentAfterQuarantine(t *testing.T) {
	r := newEnrollRig(t, true)
	m := r.machine()
	defer m.J.Close()
	quarantineV2(t, r, m)
	stuck := r.account(m).Run
	r.target.password = "Reset-By-Operator-1!"
	if _, err := r.enroll(m, "Reset-By-Operator-1!"); err != nil {
		t.Fatal(err)
	}
	a := r.account(m)
	cur := r.current(m)
	if a.Quarantined || cur.Envelope.SecretVersion != 3 || !cur.VaultCommitted || a.Run.Reason != pqcrypto.ReasonSuperseded {
		t.Fatalf("after re-enrollment: quarantined=%v current=%d run=%+v", a.Quarantined, cur.Envelope.SecretVersion, a.Run)
	}
	chains, _ := r.cp.Store.Vault().Chains(context.Background(), string(r.pol.AccountID))
	byVersion := map[uint64]*store.StoredChain{}
	for _, c := range chains {
		byVersion[c.Envelope.SecretVersion] = c
	}
	if len(byVersion[1].Receipts) != 2 || len(byVersion[2].Receipts) != 1 || byVersion[2].Receipts[0].ReceiptType != "abort" || len(byVersion[3].Receipts) != 1 {
		t.Fatalf("chains v1=%d v2=%d v3=%d", len(byVersion[1].Receipts), len(byVersion[2].Receipts), len(byVersion[3].Receipts))
	}
	if run, _ := r.cp.Store.Vault().GetRun(context.Background(), string(r.pol.AccountID), string(stuck.OperationID)); run.State != "aborted" {
		t.Fatalf("stuck run %s", run.State)
	}
	if r.cpLock() != "" {
		t.Fatalf("lock %s", r.cpLock())
	}
	if err := m.Rotate(context.Background(), r.pol.AccountID, 1, due.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if a := r.account(m); a.Run.State != broker.StateReleaseAuthorized || a.Run.SecretVersion != 4 {
		t.Fatalf("next rotation %+v", a.Run)
	}
}

// §13 1A acceptance test 4: losing the Control Plane's acknowledgement makes the broker
// re-send its receipts without a second bind.
func TestEnrollmentResendsWithoutASecondBind(t *testing.T) {
	r := newEnrollRig(t, true)
	m := r.machine()
	quarantineV2(t, r, m)
	r.target.password = "Reset-By-Operator-1!"
	m.Hook = func(p string) error {
		if p == "before_enroll_send" {
			return errors.New("kill")
		}
		return nil
	}
	if _, err := r.enroll(m, "Reset-By-Operator-1!"); !errors.Is(err, broker.ErrStopped) {
		t.Fatal(err)
	}
	m.J.Close()
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := r.target.logins["Reset-By-Operator-1!"]; n != 1 {
		t.Fatalf("%d binds", n)
	}
	if a := r.account(m2); a.Quarantined || !a.Enrollment.Sent {
		t.Fatalf("%+v", a.Enrollment)
	}
}

// failReceipts fails the next n receipt deliveries, as a transient error on an open channel.
type failReceipts struct {
	broker.ControlPlane
	n int
}

func (f *failReceipts) Receipts(ctx context.Context, op, account pqcrypto.UUID, rs []pqcrypto.B64) error {
	if f.n > 0 {
		f.n--
		return errors.New("transient")
	}
	return f.ControlPlane.Receipts(ctx, op, account, rs)
}

// A receipt delivery that fails while the channel stays open is retried by the next
// scheduler tick, with no reconnect and no second bind (PR #15 review).
func TestEnrollmentReceiptsRetryOnTheNextTick(t *testing.T) {
	r := newEnrollRig(t, true)
	m := r.machine()
	defer m.J.Close()
	quarantineV2(t, r, m)
	r.target.password = "Reset-By-Operator-1!"
	m.CP = &failReceipts{ControlPlane: m.CP, n: 1}
	if _, err := r.enroll(m, "Reset-By-Operator-1!"); err == nil {
		t.Fatal("the first delivery did not fail")
	}
	if a := r.account(m); !a.Enrollment.Open() || r.cpLock() == "" {
		t.Fatalf("delivered: sent=%v lock=%q", a.Enrollment.Sent, r.cpLock())
	}
	if err := m.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := r.account(m); a.Quarantined || !a.Enrollment.Sent || r.cpLock() != "" {
		t.Fatalf("after the tick: quarantined=%v sent=%v lock=%q", a.Quarantined, a.Enrollment.Sent, r.cpLock())
	}
	if n := r.target.logins["Reset-By-Operator-1!"]; n != 1 {
		t.Fatalf("%d binds", n)
	}
}

// §13 1A acceptance test 4: an acceptance withheld past 15 minutes expires the
// reservation; the broker never binds and the stuck rotation's lock is restored. A failed
// enrollment restores it too.
func TestExpiredOrFailedEnrollmentRestoresTheStuckLock(t *testing.T) {
	for _, expired := range []bool{true, false} {
		r := newEnrollRig(t, true)
		m := r.machine()
		quarantineV2(t, r, m)
		stuck := r.cpLock()
		r.target.password = "Reset-By-Operator-1!"
		at, pw := time.Now().UTC(), "wrong-Passw0rd"
		if expired {
			at, pw = at.Add(-16*time.Minute), "Reset-By-Operator-1!"
		}
		e, _ := r.submit(r.alice, pw, at)
		if err := m.Enroll(context.Background(), e.Tx, e.Envelope); err != nil {
			t.Fatal(err)
		}
		a := r.account(m)
		m.J.Close()
		if !a.Quarantined || a.Enrollment.Verified || r.cpLock() != stuck {
			t.Fatalf("expired=%v: quarantined=%v lock=%s want %s", expired, a.Quarantined, r.cpLock(), stuck)
		}
		if binds := r.target.logins[pw]; expired && binds != 0 {
			t.Fatal("bound without accept_ack")
		}
	}
}

// §13 1A acceptance test 4: a crash after verification started and before its result
// fails the enrollment with no second bind.
func TestCrashAfterVerificationStartedFails(t *testing.T) {
	r := newEnrollRig(t, false)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "verify_started" {
			return errors.New("kill")
		}
		return nil
	}
	if _, err := r.enroll(m, initialPassword); !errors.Is(err, broker.ErrStopped) {
		t.Fatal(err)
	}
	m.J.Close()
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := r.account(m2)
	if len(r.target.logins) != 0 || a.Enrollment.Verified || !a.Enrollment.Sent {
		t.Fatalf("logins %v %+v", r.target.logins, a.Enrollment)
	}
}

// §3.4 step 5: enrollment needs a quarantined account or no open rotation, and an open
// enrollment blocks rotation.
func TestEnrollmentAndRotationExcludeEachOther(t *testing.T) {
	r := newEnrollRig(t, true)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "intent" {
			return errors.New("kill")
		}
		return nil
	}
	m.Rotate(context.Background(), r.pol.AccountID, 0, due) // stopped with an open, healthy run
	m.Hook = nil
	e, _ := r.submitOver(r.alice, initialPassword)
	if err := m.Enroll(context.Background(), e.Tx, e.Envelope); !errors.Is(err, broker.ErrBlocked) {
		t.Fatalf("enroll during a rotation: %v", err)
	}
	m.J.Close()

	r2 := newEnrollRig(t, false)
	m2 := r2.machine()
	defer m2.J.Close()
	m2.Hook = func(p string) error {
		if p == "verify_started" {
			return errors.New("kill")
		}
		return nil
	}
	r2.enroll(m2, initialPassword)
	m2.Hook = nil
	if err := m2.Rotate(context.Background(), r2.pol.AccountID, 0, due); !errors.Is(err, broker.ErrBlocked) {
		t.Fatalf("rotate during an enrollment: %v", err)
	}
}

// submitOver reserves on the Control Plane even though a rotation lock is held, as a
// Control Plane that ignores its own rule would, to test the broker's check.
func (r *enrollRig) submitOver(who *pqtest.Principal, password string) (*cli.Enrollment, pqcrypto.UUID) {
	r.T.Helper()
	ctx := context.Background()
	if err := r.cp.Store.Vault().SetHealth(ctx, string(r.pol.AccountID), broker.HealthQuarantined, "lie"); err != nil {
		r.T.Fatal(err)
	}
	return r.submit(who, password, time.Now().UTC())
}

// A candidate sealed to anyone but the active broker is refused before any bind, even
// under a valid enroll transaction over its digest (§3.5).
func TestCandidateWithAForeignRecipientIsRefused(t *testing.T) {
	r := newEnrollRig(t, false)
	m := r.machine()
	defer m.J.Close()
	reqID := pqtest.UUID()
	op, _ := pqcrypto.RequestOpID(reqID, 0)
	v, err := r.cp.Store.Vault().ReserveEnrollment(context.Background(), string(r.pol.AccountID), string(op), 0, time.Now().UTC(), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tr := r.cliTrust()
	pol, pd := tr.Policy(r.pol.AccountID)
	stranger := pqtest.NewPrincipal(t)
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: r.cp.Dep.ID, Epoch: pol.Epoch, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: pol.AccountID}, SignerRole: pqcrypto.RoleUser}
	env, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), pqcrypto.Counter(v), pd.Hex(), 0, time.Now(), []byte(initialPassword),
		[]pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(r.B.ID), Pub: stranger.Enc.Public().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	pqcrypto.Sign(env, pqcrypto.RoleUser, r.alice.Sig)
	ed, _ := pqcrypto.ObjDigest(env)
	txRaw, tx := r.cp.Dep.Tx(t, pol, r.B.ID, r.alice, pqcrypto.Action{ActionType: pqcrypto.ActionEnroll, EnvelopeDigest: ed.Hex(), SecretVersion: pqcrypto.Counter(v)}, time.Now())
	tx.RequestID = reqID
	tx.Signatures = nil
	pqcrypto.Sign(tx, pqcrypto.RoleUser, r.alice.Sig)
	txRaw = pqtest.Canon(t, tx)
	if err := m.Enroll(context.Background(), txRaw, pqtest.Canon(t, env)); !errors.Is(err, pqcrypto.ErrRecipients) {
		t.Fatalf("got %v", err)
	}
	if len(r.target.logins) != 0 || r.account(m).Enrollment != nil {
		t.Fatal("touched the target or journaled a refused candidate")
	}
}

// Security review of #15: a broker-signed envelope of another account, even at the
// reserved version and under a valid enroll over its digest, is refused before any login.
func TestAnotherAccountsEnvelopeIsNotACandidate(t *testing.T) {
	r := newEnrollRig(t, false)
	m := r.machine()
	defer m.J.Close()
	other := r.cp.Account(func(p *pqcrypto.PolicyManifest) { p.EnrollerPrincipalIDs = []pqcrypto.UUID{r.alice.ID} })
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqID := pqtest.UUID()
	op, _ := pqcrypto.RequestOpID(reqID, 0)
	v, err := r.cp.Store.Vault().ReserveEnrollment(context.Background(), string(r.pol.AccountID), string(op), 0, time.Now().UTC(), 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	tr := r.cliTrust()
	opol, od := tr.Policy(other.AccountID)
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: r.cp.Dep.ID, Epoch: opol.Epoch, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: other.AccountID}, SignerRole: pqcrypto.RoleBroker}
	env, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), pqcrypto.Counter(v), od.Hex(), 0, time.Now(), []byte("other-account-Passw0rd"),
		[]pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(r.B.ID), Pub: r.B.Enc.Public().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	pqcrypto.Sign(env, pqcrypto.RoleBroker, r.B.Sig)
	ed, _ := pqcrypto.ObjDigest(env)
	pol, _ := tr.Policy(r.pol.AccountID)
	_, tx := r.cp.Dep.Tx(t, pol, r.B.ID, r.alice, pqcrypto.Action{ActionType: pqcrypto.ActionEnroll, EnvelopeDigest: ed.Hex(), SecretVersion: pqcrypto.Counter(v)}, time.Now())
	tx.RequestID, tx.Signatures = reqID, nil
	pqcrypto.Sign(tx, pqcrypto.RoleUser, r.alice.Sig)
	if err := m.Enroll(context.Background(), pqtest.Canon(t, tx), pqtest.Canon(t, env)); !errors.Is(err, broker.ErrNotCandidate) {
		t.Fatalf("got %v", err)
	}
	if len(r.target.logins) != 0 || r.account(m).Enrollment != nil {
		t.Fatal("logged in or journaled")
	}
}

// An accepted enrollment resumed after a restart, when sync has since applied a policy
// that pins another target, fails without sending the credential anywhere (security review
// of #15).
func TestRecoveredEnrollmentFailsWhenTheTargetChanged(t *testing.T) {
	r := newEnrollRig(t, false)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "accept_ack" {
			return errors.New("kill")
		}
		return nil
	}
	if _, err := r.enroll(m, initialPassword); !errors.Is(err, broker.ErrStopped) {
		t.Fatal(err)
	}
	m.J.Close()
	moveTarget(t, r.rig)
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if p, _ := m2.Trust.Policy(r.pol.AccountID); p.Epoch != 2 {
		t.Fatalf("policy epoch %s", p.Epoch)
	}
	m2.Recover(context.Background())
	if n := r.target.logins[initialPassword]; n != 0 || len(r.target.hosts) != 0 {
		t.Fatalf("%d logins to %v", n, r.target.hosts)
	}
	if a := r.account(m2); a.Enrollment.Verified || r.current(m2) != nil {
		t.Fatalf("enrollment %+v", a.Enrollment)
	}
}
