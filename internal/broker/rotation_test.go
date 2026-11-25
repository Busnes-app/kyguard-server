package broker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
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
	if run, _ := r.cp.Store.Vault().GetRun(context.Background(), string(r.pol.AccountID), string(a.Run.OperationID)); run == nil || run.State != "release_authorized" {
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
		// Between commit_target and release: the restart signs release and finishes
		// (PR Reviewer Guide on #11).
		{"target_verified", 1, broker.StateReleaseAuthorized, false},
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
	if a := r.account(m); a.Run.State != broker.StateReserving || len(a.Run.NewEnvelope) > 0 || a.HighestVersion != 1 {
		t.Fatalf("journaled %+v", a.Run)
	}
	if _, writes := r.target.state(); writes != 0 {
		t.Fatal("wrote")
	}
}

// A reservation the Control Plane committed while the broker never journaled its reply
// (a crash or a lost response) is settled after sync and recovery: the same operation's
// version is accepted, aborted with nothing written, its lock released, and rotation
// resumes (security review of #11).
func TestACommittedReservationWithoutAPreparedRunIsSettled(t *testing.T) {
	r := newRig(t)
	real := r.cpw
	w := &wrapCP{ControlPlane: real}
	w.reserve = func(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
		if _, err := real.Reserve(ctx, account, op, reported); err != nil {
			return 0, err
		}
		return 0, errors.New("connection lost") // the reply never reaches the journal
	}
	r.cpw = w
	m := r.machine()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err == nil {
		t.Fatal("rotate succeeded without a reservation reply")
	}
	op := r.account(m).Run.OperationID
	if r.cpLock() != string(op) {
		t.Fatalf("lock %q, want the reserving run %s", r.cpLock(), op)
	}
	m.J.Close()
	w.reserve = nil
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := r.account(m2)
	if a.Run.OperationID != op || a.Run.State != broker.StateAborted || !a.Run.Sent || r.cpLock() != "" {
		t.Fatalf("run %+v lock %q", a.Run, r.cpLock())
	}
	if _, writes := r.target.state(); writes != 0 {
		t.Fatal("a settled reservation wrote to the target")
	}
	if err := m2.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatalf("rotation after settling: %v", err)
	}
	if a := r.account(m2); a.Run.State != broker.StateReleaseAuthorized || a.Run.Attempt != 1 {
		t.Fatalf("next run %+v", a.Run)
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

	real := &brokerproto.SyncReply{}
	for req := (brokerproto.SyncRequest{}); ; {
		page, err := r.cpw.Sync(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		real.Manifests, real.Accounts = append(real.Manifests, page.Manifests...), append(real.Accounts, page.Accounts...)
		if page.Done {
			real.Done = true
			break
		}
		req.ManifestsAfter += len(page.Manifests)
	}
	realAcct, err := r.cpw.SyncAccount(ctx, r.pol.AccountID, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	fork := p2
	fork.Signatures, fork.MaxCheckoutTTLSeconds = nil, 60
	old := *r.pol
	old.Signatures = nil
	stale := *real
	stale.Manifests = append(append([]pqcrypto.B64(nil), real.Manifests...), r.cp.Dep.Signed(t, &old), r.cp.Dep.Signed(t, &fork))
	st := *realAcct
	st.Chains = append([]brokerproto.ChainState(nil), st.Chains...)
	last := st.Chains[len(st.Chains)-1]
	last.Receipts = last.Receipts[:1] // the latest release is missing
	st.Chains[len(st.Chains)-1] = last
	m.CP = &wrapCP{ControlPlane: r.cpw,
		sync: func(context.Context, brokerproto.SyncRequest) (*brokerproto.SyncReply, error) { return &stale, nil },
		account: func(context.Context, pqcrypto.UUID, pqcrypto.Counter, pqcrypto.Counter) (*brokerproto.AccountState, error) {
			return &st, nil
		}}
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

// The broker follows sync pages to the end (PR Reviewer Guide on #10).
func TestSyncFollowsEveryPage(t *testing.T) {
	r := newRig(t)
	var ids []pqcrypto.UUID
	for range brokerproto.SyncPage + 3 {
		ids = append(ids, r.cp.Account(nil).AccountID)
	}
	m := r.machine()
	defer m.J.Close()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if p, _ := m.Trust.Policy(id); p == nil {
			t.Fatalf("policy of %s not synced", id)
		}
	}
}

// An account sync keeps its AfterVersion and continues from the highest version received
// until the Control Plane has no more (security review of #10).
func TestAccountSyncContinuesFromTheLastVersion(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	defer m.J.Close()
	env := func(v pqcrypto.Counter) brokerproto.ChainState {
		raw, _ := json.Marshal(struct {
			V pqcrypto.Counter `json:"secret_version"`
		}{v})
		return brokerproto.ChainState{Envelope: raw, Receipts: []pqcrypto.B64{}}
	}
	var asked [][2]pqcrypto.Counter
	m.CP = &wrapCP{ControlPlane: r.cpw, account: func(_ context.Context, id pqcrypto.UUID, after, from pqcrypto.Counter) (*brokerproto.AccountState, error) {
		asked = append(asked, [2]pqcrypto.Counter{after, from})
		st := &brokerproto.AccountState{AccountID: id, Chains: []brokerproto.ChainState{env(from + 1), env(from + 2)}, More: from < 4}
		return st, nil
	}}
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(asked) != "[[1 0] [1 2] [1 4]]" { // the rig's broker holds version 1
		t.Fatalf("requests (after, from) = %v", asked)
	}
}

// moveTarget signs policy epoch 2 pointing the account at another host.
func moveTarget(t *testing.T, r *rig) {
	t.Helper()
	raw, dg := r.cp.Dep.SSHTarget(t, r.pol.AccountID, pqtest.UUID(), "db2.example.test", 22, "svc", pqcrypto.HexID(strings.Repeat("cd", 32)))
	if err := r.cp.Store.Vault().PutTargetDescriptor(context.Background(), string(dg), string(r.pol.AccountID), raw); err != nil {
		t.Fatal(err)
	}
	p2 := *r.pol
	p2.Signatures, p2.Epoch, p2.TargetDescriptorDigest = nil, 2, dg
	r.cp.Submit(r.cp.Dep.Signed(t, &p2))
}

// §3.3, §13 1A acceptance test 6 (security review of #11): after the descriptor changes,
// the envelope sealed for the old target is never sent to the new one.
func TestDescriptorChangeNeedsEnrollment(t *testing.T) {
	r := newRig(t)
	moveTarget(t, r)
	m := r.machine()
	defer m.J.Close()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); !errors.Is(err, broker.ErrNeedsEnrollment) {
		t.Fatalf("got %v", err)
	}
	if len(r.target.hosts) != 0 {
		t.Fatalf("logged into %v", r.target.hosts)
	}
	if a := r.account(m); a.Health != broker.HealthNeedsEnrollment {
		t.Fatalf("health %s", a.Health)
	}
}

// Recovery probes the target the intent was for, not a descriptor that arrived since.
func TestRecoveryProbesTheOriginalTarget(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "after_write" {
			return errors.New("kill")
		}
		return nil
	}
	m.Rotate(context.Background(), r.pol.AccountID, 0, due)
	m.J.Close()
	moveTarget(t, r)
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.target.hosts = nil
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.target.hosts) != 1 || r.target.hosts[0] != "db1.example.test" {
		t.Fatalf("probed %v", r.target.hosts)
	}
}

// An aborted run whose receipts were not delivered is not replaced by the next rotation: the
// next attempt delivers the abort first, or stays blocked (PR Reviewer Guide on #11).
func TestUndeliveredAbortIsSentBeforeTheNextRun(t *testing.T) {
	r := newRig(t)
	r.target.refuseBeforeCommit = true
	w := &wrapCP{ControlPlane: r.cpw, receiptsErr: errors.New("control plane unreachable")}
	r.cpw = w
	m := r.machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err == nil {
		t.Fatal("delivery did not fail")
	}
	r.target.refuseBeforeCommit = false
	first := r.account(m).Run
	if first.State != broker.StateAborted || first.Sent {
		t.Fatalf("first run %+v", first)
	}
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); !errors.Is(err, broker.ErrBlocked) {
		t.Fatalf("undelivered abort: %v", err)
	}
	if a := r.account(m); a.Run.OperationID != first.OperationID || a.Run.Sent || r.cpLock() != string(first.OperationID) {
		t.Fatalf("pending abort lost: run %+v lock %s", a.Run, r.cpLock())
	}
	w.receiptsErr = nil
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	// The second run could reserve only because the abort released the first one's lock.
	a := r.account(m)
	if a.Run.State != broker.StateReleaseAuthorized || a.Run.Attempt != 1 || r.cpLock() != "" {
		t.Fatalf("second run %+v lock %s", a.Run, r.cpLock())
	}
	if !slices.ContainsFunc(a.Chains, func(c broker.ChainCopy) bool { return slices.Equal(c.Envelope, first.NewEnvelope) }) {
		t.Fatal("the delivered abort did not join the broker's copy")
	}
}

// Health whose report failed is sent again on reconnect (PR Reviewer Guide on #11).
func TestUndeliveredHealthIsResentOnRecover(t *testing.T) {
	r := newRig(t)
	r.target.ambiguous = errors.New("connection reset") // not applied: the probe fails
	w := &wrapCP{ControlPlane: r.cpw, statusErr: errors.New("control plane unreachable")}
	r.cpw = w
	m := r.machine()
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); err != nil {
		t.Fatal(err)
	}
	if a := r.account(m); !a.Quarantined || !a.Unreported || r.cpAccount().Health == broker.HealthQuarantined {
		t.Fatalf("quarantined=%v unreported=%v cp health=%s", a.Quarantined, a.Unreported, r.cpAccount().Health)
	}
	m.J.Close()
	w.statusErr = nil
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := r.cpAccount().Health; h != broker.HealthQuarantined {
		t.Fatalf("control plane health %s", h)
	}
	if r.account(m2).Unreported {
		t.Fatal("still unreported after delivery")
	}
}

// A crash after a quarantine is journaled and before its health reaches the Control Plane
// leaves it to be sent by recovery, without another probe (security review of #11).
func TestQuarantineHealthSurvivesACrashBeforeItsReport(t *testing.T) {
	r := newRig(t)
	r.target.ambiguous = errors.New("connection reset") // not applied: the probe fails
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "quarantined" {
			return errors.New("crash")
		}
		return nil
	}
	if err := m.Rotate(context.Background(), r.pol.AccountID, 0, due); !errors.Is(err, broker.ErrStopped) {
		t.Fatalf("rotate: %v", err)
	}
	if a := r.account(m); !a.Quarantined || !a.Unreported || r.cpAccount().Health == broker.HealthQuarantined {
		t.Fatalf("quarantined=%v unreported=%v cp health=%s", a.Quarantined, a.Unreported, r.cpAccount().Health)
	}
	m.J.Close()
	logins := func() (n int) {
		for _, c := range r.target.logins {
			n += c
		}
		return n
	}
	before := logins()
	m2 := r.machine()
	defer m2.J.Close()
	if err := m2.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h := r.cpAccount().Health; h != broker.HealthQuarantined {
		t.Fatalf("control plane health %s after recovery", h)
	}
	if a := r.account(m2); a.Unreported {
		t.Fatal("still unreported after delivery")
	}
	if logins() != before {
		t.Fatal("recovery logged in to the target again")
	}
}

// Account pages follow accounts_next: a page whose accounts were all filtered out still
// advances, and a page that does not advance is refused (PR Reviewer Guide on #10).
func TestSyncFollowsTheAccountCursor(t *testing.T) {
	r := newRig(t)
	m := r.machine()
	defer m.J.Close()
	ctx := context.Background()
	var asked []pqcrypto.UUID
	stuck := false
	m.CP = &wrapCP{ControlPlane: r.cpw, sync: func(_ context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error) {
		asked = append(asked, req.AccountsAfter)
		switch {
		case stuck:
			return &brokerproto.SyncReply{Accounts: []pqcrypto.UUID{}, AccountsNext: req.AccountsAfter}, nil
		case req.AccountsAfter == "":
			return &brokerproto.SyncReply{Accounts: []pqcrypto.UUID{}, AccountsNext: "00000000-0000-7000-8000-000000000001"}, nil
		}
		return &brokerproto.SyncReply{Accounts: []pqcrypto.UUID{r.pol.AccountID}, Done: true}, nil
	}}
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if len(asked) != 2 || asked[1] != "00000000-0000-7000-8000-000000000001" {
		t.Fatalf("pages asked after %v", asked)
	}
	stuck = true
	if err := m.Sync(ctx); err == nil || !strings.Contains(err.Error(), "no progress") {
		t.Fatalf("a page that does not advance: %v", err)
	}
}

// A manifest whose journal append failed is persisted by the next sync, so it survives a
// restart (Guide on #11, "Lost manifest").
func TestFailedManifestAppendIsPersistedOnRetry(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	r.cp.Submit(r.cp.Dep.Signed(t, r.cp.Dep.ManagedPolicy(r.pol.AccountID, r.pol.PoolID, 2, r.pol.TargetDescriptorDigest)))
	m := r.machine()
	m.Hook = func(p string) error {
		if p == "append_manifest" {
			return errors.New("disk full")
		}
		return nil
	}
	if err := m.Sync(ctx); err == nil {
		t.Fatal("the failed append was not reported")
	}
	m.Hook = nil
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	m.J.Close()
	m2 := r.machine()
	defer m2.J.Close()
	if p, _ := m2.Trust.Policy(r.pol.AccountID); p == nil || p.Epoch != 2 {
		t.Fatalf("after a restart the policy is %+v", p)
	}
}
