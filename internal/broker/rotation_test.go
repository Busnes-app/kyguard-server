package broker_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

var due = time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)

func TestNewPasswordShape(t *testing.T) {
	for range 200 {
		p := string(broker.NewPassword())
		if len(p) != 32 || !strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") || !strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") ||
			!strings.ContainsAny(p, "0123456789") || !strings.ContainsAny(p, "-_.!@") || strings.Trim(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!@") != "" {
			t.Fatalf("password %q", p)
		}
	}
}

// §13 1A acceptance test 2 (fake target): a rotation reaches release_authorized, the
// Control Plane's current envelope moves, and the old password no longer authenticates.
func TestRotationReachesReleaseAuthorized(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	a := r.account(m)
	if a.Run.State != broker.StateReleaseAuthorized || !a.Run.Sent || a.Health != broker.HealthHealthy || a.Run.SecretVersion != 2 {
		t.Fatalf("run %+v health %s", a.Run, a.Health)
	}
	pw, writes := r.target.state()
	if writes != 1 || pw == initialPassword {
		t.Fatalf("target writes=%d", writes)
	}
	if err := r.target.login([]byte(initialPassword)); err == nil {
		t.Fatal("the old password still authenticates")
	}
	ca := r.cpAccount()
	env, _ := m.Trust.VerifyEnvelope(a.Run.NewEnvelope, pqcrypto.EnvelopeContext{})
	if ca.CurrentEnvelopeID != string(env.EnvelopeID) || r.cpLock() != "" || ca.Health != broker.HealthHealthy {
		t.Fatalf("control plane current=%s lock=%s health=%s", ca.CurrentEnvelopeID, r.cpLock(), ca.Health)
	}
	if run, _ := r.cp.Store.Vault().GetRun(context.Background(), string(a.Run.OperationID)); run == nil || run.State != "release_authorized" {
		t.Fatalf("control plane run %+v", run)
	}
	// The next rotation opens the new current envelope.
	if err := m.Rotate(context.Background(), r.pol.AccountID, 1, due.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, writes := r.target.state(); writes != 2 {
		t.Fatalf("second rotation writes=%d", writes)
	}
}

// §13 1A acceptance test 3: a crash at each point, then a restart.
func TestCrashThenRestart(t *testing.T) {
	cases := []struct {
		point     string
		writes    int    // writes that reached the target in total
		state     string // run state after the restart
		quarantin bool
	}{
		// No write was sent: aborted, target unchanged.
		{"prepared", 0, broker.StateAborted, false},
		{"intent", 0, broker.StateAborted, false},
		// ack_received is durable but the write had not left: the restart never writes; the
		// one probe fails, so quarantine (never aborted).
		{"ack_received", 0, broker.StateWriteOutcomeUnknown, true},
		// The write reached the target, then the broker died: the probe verifies.
		{"after_write", 1, broker.StateReleaseAuthorized, false},
		// The probe was journaled and never sent: it counts as used.
		{"probe_recorded", 1, broker.StateWriteOutcomeUnknown, true},
		// The result was journaled and not delivered: re-sent, no second write.
		{"before_send", 1, broker.StateReleaseAuthorized, false},
	}
	for _, c := range cases {
		t.Run(c.point, func(t *testing.T) {
			r := newRig(t)
			m := r.machine()
			m.Hook = func(p string) error {
				if p == c.point {
					return errors.New("kill")
				}
				return nil
			}
			if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); !errors.Is(err, broker.ErrStopped) {
				t.Fatalf("rotate: %v", err)
			}
			m.J.Close()
			logins := r.target.logins
			_ = logins
			m2 := r.machine()
			defer m2.J.Close()
			if err := m2.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			a := r.account(m2)
			_, writes := r.target.state()
			if writes != c.writes || a.Run.State != c.state || a.Quarantined != c.quarantin {
				t.Fatalf("writes=%d state=%s quarantined=%v", writes, a.Run.State, a.Quarantined)
			}
			if c.state == broker.StateAborted && (a.Run.Reason != pqcrypto.ReasonRestartBeforeSend || r.cpLock() != "") {
				t.Fatalf("abort reason=%s lock=%s", a.Run.Reason, r.cpLock())
			}
			if c.quarantin && (r.cpAccount().Health != broker.HealthQuarantined || r.cpLock() == "") {
				t.Fatalf("control plane health=%s lock=%q: a quarantined account stays locked", r.cpAccount().Health, r.cpLock())
			}
			// A second restart changes nothing and never writes.
			m2.J.Close()
			m3 := r.machine()
			defer m3.J.Close()
			if err := m3.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, w := r.target.state(); w != c.writes {
				t.Fatalf("second restart wrote: %d", w)
			}
		})
	}
}

// A probe recorded without a result is never sent after the restart.
func TestRecordedProbeIsNotResent(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "probe_recorded" {
			return errors.New("kill")
		}
		return nil
	}
	m.Rotate(context.Background(), r.pol.AccountID, 0, due)
	m.J.Close()
	pw, _ := r.target.state()
	before := r.target.logins[pw]
	m2 := r.machine()
	defer m2.J.Close()
	m2.Recover(context.Background())
	if r.target.logins[pw] != before {
		t.Fatal("the recorded probe was sent again")
	}
}

// §13 1A acceptance test 3: an acknowledgement withheld past the timeout aborts with the
// target unchanged; the late acknowledgement is ignored.
func TestWithheldAckAborts(t *testing.T) {
	r := newRig(t)
	late := make(chan error, 1)
	inner := r.cpw
	r.cpw = &wrapCP{ControlPlane: inner, intent: func(ctx context.Context, raw []byte) error {
		<-ctx.Done()
		late <- inner.Intent(context.Background(), raw) // the Control Plane records it after all
		return ctx.Err()
	}}
	m := r.machine()
	defer m.J.Close()
	m.AckTimeout = 50 * time.Millisecond
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	a := r.account(m)
	if _, writes := r.target.state(); writes != 0 || a.Run.State != broker.StateAborted || a.Run.Reason != pqcrypto.ReasonRestartBeforeSend || a.Run.AckReceived {
		t.Fatalf("writes=%d run=%+v", writes, a.Run)
	}
	if err := <-late; err != nil {
		t.Logf("late intent: %v", err)
	}
	if r.cpLock() != "" {
		t.Fatal("the abort did not release the lock")
	}
}

func TestAmbiguousWriteGetsOneProbe(t *testing.T) {
	for _, applied := range []bool{true, false} {
		r := newRig(t)
		r.target.ambiguous, r.target.applyAmbiguous = errors.New("connection reset"), applied
		m := r.machine()
		if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
			t.Fatal(err)
		}
		a := r.account(m)
		m.J.Close()
		if applied && (a.Run.State != broker.StateReleaseAuthorized || a.Quarantined) {
			t.Fatalf("applied: %+v", a.Run)
		}
		if !applied && (a.Run.State != broker.StateWriteOutcomeUnknown || !a.Quarantined || a.Run.State == broker.StateAborted) {
			t.Fatalf("not applied: %+v quarantined=%v", a.Run, a.Quarantined)
		}
	}
}

// §4.4: a deterministic refusal ends aborted (refused) with health rotation_failed, before
// or after the intent; the password is unchanged.
func TestRefusalAborts(t *testing.T) {
	for _, before := range []bool{true, false} {
		r := newRig(t)
		r.target.refuseBeforeCommit, r.target.refuseAfterCommit = before, !before
		m := r.machine()
		if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
			t.Fatal(err)
		}
		a := r.account(m)
		m.J.Close()
		if pw, writes := r.target.state(); writes != 0 || pw != initialPassword || a.Run.State != broker.StateAborted ||
			a.Run.Reason != pqcrypto.ReasonRefused || a.Health != broker.HealthRotationFailed || r.cpLock() != "" {
			t.Fatalf("before=%v run=%+v health=%s", before, a.Run, a.Health)
		}
	}
}

// §4.6: a credential that no longer authenticates stops after one attempt and quarantines.
func TestAuthFailureStopsAfterOneAttempt(t *testing.T) {
	r := newRig(t)
	r.target.password = "changed-out-of-band"
	m := r.machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	a := r.account(m)
	if r.target.failed != 1 || !a.Quarantined || a.Health != broker.HealthAuthFailed || a.Run.State != broker.StateAborted {
		t.Fatalf("failed=%d %+v", r.target.failed, a)
	}
	if err := m.Rotate(context.Background(), r.pol.AccountID, 1, due); !errors.Is(err, broker.ErrQuarantined) || r.target.failed != 1 {
		t.Fatalf("second attempt: %v, failed logins %d", err, r.target.failed)
	}
}

// §13 1A acceptance test 6: a reserved secret_version at or below the highest seen is
// refused before anything is sealed.
func TestReservedVersionMustBeAboveTheHighestSeen(t *testing.T) {
	r := newRig(t)
	r.cpw = &wrapCP{ControlPlane: r.cpw, reserve: func(_ context.Context, _, _ pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
		return reported, nil
	}}
	m := r.machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); !errors.Is(err, broker.ErrStaleVersion) {
		t.Fatalf("got %v", err)
	}
	if a := r.account(m); a.Run != nil {
		t.Fatalf("journaled %+v", a.Run)
	}
	if _, writes := r.target.state(); writes != 0 {
		t.Fatal("wrote")
	}
}

// §4.2 blocking rule: an open rotation refuses another.
func TestOpenRotationBlocksTheAccount(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "ack_received" {
			return errors.New("kill")
		}
		return nil
	}
	m.Rotate(context.Background(), r.pol.AccountID, 0, due)
	m.Hook = nil
	if err := m.Rotate(context.Background(), r.pol.AccountID, 1, due); !errors.Is(err, broker.ErrBlocked) {
		t.Fatalf("got %v", err)
	}
	m.J.Close()
}

// §13 1A acceptance test 6: an older policy epoch, a different policy at the same epoch,
// or a receipt chain older than the broker's copy is refused and alerted; a policy epoch
// change leaves the current envelope usable.
func TestSyncRefusesRollbackForksAndStaleChains(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	m := r.machine()
	defer m.J.Close()
	if err := m.Rotate(ctx, r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	p2 := *r.pol
	p2.Signatures, p2.Epoch = nil, 2
	p2.MaxCheckoutTTLSeconds = 600
	raw2 := r.cp.Dep.Signed(t, &p2)
	r.cp.Submit(raw2)
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if p, _ := m.Trust.Policy(r.pol.AccountID); p.Epoch != 2 {
		t.Fatalf("epoch %s", p.Epoch)
	}
	// The envelope sealed under epoch 1 still opens and rotates under epoch 2.
	if err := m.Rotate(ctx, r.pol.AccountID, 0, due); err != nil {
		t.Fatalf("rotate after the policy change: %v", err)
	}

	real, err := r.cpw.Sync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fork := p2
	fork.Signatures, fork.MaxCheckoutTTLSeconds = nil, 60
	old := *r.pol
	old.Signatures = nil
	stale := *real
	stale.Accounts = []brokerproto.AccountState{real.Accounts[0]}
	st := stale.Accounts[0]
	st.Chains = append([]brokerproto.ChainState(nil), st.Chains...)
	last := st.Chains[len(st.Chains)-1]
	last.Receipts = last.Receipts[:1] // the latest release is missing
	st.Chains[len(st.Chains)-1] = last
	stale.Accounts[0] = st
	stale.Manifests = append(append([]pqcrypto.B64(nil), real.Manifests...), r.cp.Dep.Signed(t, &old), r.cp.Dep.Signed(t, &fork))
	m.CP = &wrapCP{ControlPlane: r.cpw, sync: func(context.Context) (*brokerproto.SyncReply, error) { return &stale, nil }}
	r.alerts = nil
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	want := []string{string(pqcrypto.ErrRollback), string(pqcrypto.ErrEquivocation), string(pqcrypto.ErrChain)}
	for _, w := range want {
		found := false
		for _, a := range r.alerts {
			found = found || strings.Contains(a, w)
		}
		if !found {
			t.Fatalf("no alert for %s in %q", w, r.alerts)
		}
	}
	if p, _ := m.Trust.Policy(r.pol.AccountID); p.MaxCheckoutTTLSeconds != 600 {
		t.Fatal("a refused policy took effect")
	}
	a := r.account(m)
	if n := len(a.Chains[len(a.Chains)-1].Receipts); n != 2 {
		t.Fatalf("the broker's copy was truncated to %d receipts", n)
	}
}

// §4.6 (security review of #11): the quarantine after a denied login is durable even when
// the abort cannot be delivered; after a restart the credential is never tried again.
func TestAuthFailureQuarantineSurvivesAFailedDelivery(t *testing.T) {
	r := newRig(t)
	r.target.password = "changed-out-of-band"
	w := &wrapCP{ControlPlane: r.cpw, receiptsErr: errors.New("control plane unreachable")}
	r.cpw = w
	m := r.machine()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err == nil {
		t.Fatal("delivery did not fail")
	}
	m.J.Close()
	w.receiptsErr = nil
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m2.Rotate(context.Background(), r.pol.AccountID, 1, due); !errors.Is(err, broker.ErrQuarantined) {
		t.Fatalf("after restart: %v", err)
	}
	if r.target.failed != 1 {
		t.Fatalf("%d denied logins", r.target.failed)
	}
	if a := r.account(m2); !a.Quarantined || a.Health != broker.HealthAuthFailed || !a.Run.Sent {
		t.Fatalf("%+v", a)
	}
}
