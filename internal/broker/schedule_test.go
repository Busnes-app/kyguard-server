package broker_test

import (
	"context"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

const day = 24 * time.Hour

func TestOutstanding(t *testing.T) {
	anchor := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(anchor), IntervalSeconds: 86400}
	for _, c := range []struct {
		name  string
		floor time.Time
		now   time.Time
		k     pqcrypto.Counter
		ok    bool
	}{
		{"before the anchor", time.Time{}, anchor.Add(-time.Hour), 0, false},
		{"occurrence 0 at the anchor", time.Time{}, anchor, 0, true},
		{"latest of many", time.Time{}, anchor.Add(5*day + time.Hour), 5, true},
		{"due at the floor is not outstanding", anchor.Add(5 * day), anchor.Add(5*day + time.Hour), 0, false},
		{"due after the floor", anchor.Add(5*day - time.Second), anchor.Add(5*day + time.Hour), 5, true},
	} {
		k, at, ok := broker.Outstanding(s, &broker.Account{PolicyPersistedAt: c.floor}, c.now)
		if ok != c.ok || (ok && (k != c.k || !at.Equal(anchor.Add(time.Duration(c.k)*day)))) {
			t.Errorf("%s: k=%d at=%v ok=%v", c.name, k, at, ok)
		}
	}
}

// A daily schedule anchored ten days back, accepted now.
func scheduled(now time.Time) func(*pqcrypto.PolicyManifest) {
	return func(p *pqcrypto.PolicyManifest) {
		p.RotationSchedule = &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(now.Add(-10 * day)), IntervalSeconds: 86400}
	}
}

func clock(m *broker.Machine, t time.Time) { m.Now = func() time.Time { return t } }

// §13 1A acceptance tests 2 and 8: the broker's own clock runs the schedule with no nudge; a
// past anchor runs nothing due before the floor; repeated ticks and nudges never consume an
// occurrence twice.
func TestSchedulerRunsDueOccurrencesOnce(t *testing.T) {
	start := time.Now().UTC()
	r := newRig(t, scheduled(start))
	m := r.machine()
	defer m.J.Close()
	ctx := context.Background()

	// The anchor is ten days back, but the policy was persisted just now: nothing is due.
	clock(m, start.Add(time.Hour))
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if _, w := r.target.state(); w != 0 {
		t.Fatalf("an occurrence before the schedule floor ran: %d writes", w)
	}

	// The next occurrence falls due tomorrow.
	clock(m, start.Add(day+time.Hour))
	for range 3 { // a tick, then two nudged ticks
		if err := m.Tick(ctx); err != nil {
			t.Fatal(err)
		}
	}
	a := r.account(m)
	if _, w := r.target.state(); w != 1 || a.Run.State != broker.StateReleaseAuthorized || a.Run.Occurrence != 11 {
		t.Fatalf("writes=%d run=%+v", w, a.Run)
	}

	// Two days later the latest outstanding occurrence runs, the one before it is skipped.
	clock(m, start.Add(3*day+time.Hour))
	m.Tick(ctx)
	a = r.account(m)
	if _, w := r.target.state(); w != 2 || a.Run.Occurrence != 13 {
		t.Fatalf("writes=%d occurrence=%d", w, a.Run.Occurrence)
	}
}

// §13 1A acceptance test 9 (fake target): a refused attempt keeps the occurrence
// outstanding; the next attempt has a new operation and version and waits for
// next_attempt_at; three refusals stop the account until a new policy epoch.
func TestRefusedAttemptsRetryThenStop(t *testing.T) {
	start := time.Now().UTC()
	r := newRig(t, scheduled(start))
	r.target.refuseAfterCommit = true
	m := r.machine()
	defer m.J.Close()
	ctx := context.Background()
	now := start.Add(day + time.Hour)
	ops := map[pqcrypto.UUID]bool{}
	versions := map[pqcrypto.Counter]bool{}
	for i := range broker.MaxRefusals {
		clock(m, now)
		if err := m.Tick(ctx); err != nil {
			t.Fatal(err)
		}
		a := r.account(m)
		if a.Run.Reason != pqcrypto.ReasonRefused || a.Refusals != i+1 || a.Health != broker.HealthRotationFailed || ops[a.Run.OperationID] {
			t.Fatalf("attempt %d: refusals=%d %+v", i, a.Refusals, a.Run)
		}
		ops[a.Run.OperationID], versions[a.Run.SecretVersion] = true, true
		if want := now.Add(day); !a.NextAttemptAt.Equal(want) {
			t.Fatalf("next_attempt_at %v, want %v", a.NextAttemptAt, want)
		}
		// Not before next_attempt_at.
		clock(m, now.Add(day-time.Minute))
		m.Tick(ctx)
		if b := r.account(m); b.Run.OperationID != a.Run.OperationID {
			t.Fatal("retried before next_attempt_at")
		}
		now = now.Add(day)
	}
	if len(ops) != broker.MaxRefusals || len(versions) != broker.MaxRefusals {
		t.Fatalf("operations %d, versions %d: every attempt needs its own", len(ops), len(versions))
	}
	stopped := r.account(m).Run.OperationID
	clock(m, now.Add(30*day))
	m.Tick(ctx)
	if a := r.account(m); a.Run.OperationID != stopped {
		t.Fatal("ran after three refusals")
	}
	// A new policy epoch lifts the stop.
	r.target.refuseAfterCommit = false
	p2 := *r.pol
	p2.Signatures, p2.Epoch = nil, 2
	r.cp.Submit(r.cp.Dep.Signed(t, &p2))
	if err := m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	clock(m, now.Add(31*day))
	m.Tick(ctx)
	if a := r.account(m); a.Run.State != broker.StateReleaseAuthorized {
		t.Fatalf("after the new epoch: %+v", a.Run)
	}
}

// The known minimum-age deadline holds the next attempt back.
func TestRefusalWaitsForTheMinimumAge(t *testing.T) {
	start := time.Now().UTC()
	r := newRig(t, scheduled(start))
	r.target.refuseAfterCommit = true
	m := r.machine()
	defer m.J.Close()
	a := r.account(m)
	deadline := start.Add(5 * day)
	a.MinAgeDeadline = deadline
	m.J.Save(a)
	clock(m, start.Add(day+time.Hour))
	m.Tick(context.Background())
	if got := r.account(m).NextAttemptAt; !got.Equal(deadline) {
		t.Fatalf("next_attempt_at %v, want the minimum-age deadline %v", got, deadline)
	}
}

// §4.4, §13 1A acceptance test 9: a minimum age above the interval runs nothing.
func TestMinimumAgeAboveTheIntervalRunsNothing(t *testing.T) {
	start := time.Now().UTC()
	r := newRig(t, scheduled(start))
	m := r.machine()
	defer m.J.Close()
	a := r.account(m)
	a.MinAgeSeconds = 2 * 86400
	m.J.Save(a)
	clock(m, start.Add(day+time.Hour))
	m.Tick(context.Background())
	a = r.account(m)
	if _, w := r.target.state(); w != 0 || a.Run != nil || a.Health != broker.HealthRotationFailed || a.HealthReason != broker.ReasonBelowMinAge {
		t.Fatalf("writes=%d health=%s/%s", w, a.Health, a.HealthReason)
	}
	if ca := r.cpAccount(); ca.HealthReason != broker.ReasonBelowMinAge {
		t.Fatalf("control plane reason %q", ca.HealthReason)
	}
}
