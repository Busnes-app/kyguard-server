package broker

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// MaxRefusals is how many consecutive refused attempts stop a scheduled account until a new
// policy epoch or a manual_rotation (§4.4).
const MaxRefusals = 3

// floor is the schedule floor of §3.4: no occurrence due at or before it is outstanding.
func floor(a *Account) time.Time {
	f := a.LastConsumedDue
	for _, t := range []time.Time{a.PolicyPersistedAt, a.CurrentCommitAt} {
		if t.After(f) {
			f = t
		}
	}
	return f
}

// Outstanding returns the latest outstanding occurrence of s for a at now: due in the past
// and after the floor. Earlier outstanding occurrences are skipped, not run.
func Outstanding(s *pqcrypto.Schedule, a *Account, now time.Time) (k pqcrypto.Counter, due time.Time, ok bool) {
	if s == nil || s.IntervalSeconds <= 0 || now.Before(s.AnchorUTC.Time) {
		return 0, time.Time{}, false
	}
	interval := time.Duration(s.IntervalSeconds) * time.Second
	n := now.Sub(s.AnchorUTC.Time) / interval
	due = s.AnchorUTC.Add(n * interval)
	if !due.After(floor(a)) {
		return 0, time.Time{}, false
	}
	return pqcrypto.Counter(n), due, true
}

// Tick evaluates every account's signed schedule by the broker's own clock and runs the
// latest outstanding occurrence of each (§3.4). The Control Plane cannot cause or prevent a
// due rotation beyond withholding service; a nudge only calls Tick early.
func (m *Machine) Tick(ctx context.Context) error {
	m.mu.Lock()
	m.refusals(ctx)
	if err := m.J.PruneChallenges(m.now()); err != nil {
		log.Printf("[BROKER] expired challenges not pruned: %v", err)
	}
	accts, err := m.J.Accounts()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if err := m.hook("tick_listed"); err != nil {
		return err
	}
	var errs []error
	for _, a := range accts {
		if err := m.tick(ctx, a.ID); err != nil && !errors.Is(err, ErrNotActive) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// tick selects and starts one account's occurrence or lease cleanup under one hold of the
// mutex, so a policy accepted by a concurrent Sync is always the one checked (security
// review of #12).
func (m *Machine) tick(ctx context.Context, id pqcrypto.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.J.Account(id)
	if err != nil {
		return err
	}
	m.flush(ctx, a)
	// An open enrollment blocks rotation. Enroll holds m.mu, so one seen here stopped
	// early: it resumes as after a restart, re-sending receipts and never binding twice
	// (PR Reviewer Guide on #15).
	if a.Enrollment.Open() {
		return m.recoverEnrollment(ctx, a)
	}
	// An open run stopped part-way: Rotate holds m.mu throughout, so none is in progress
	// here. It is finished as after a restart, so a failed call never leaves it until the
	// next reconnect (decision 72; PR Reviewer Guide "Stalled rotations" on #12).
	if a.Run.Open() {
		if err := m.recover(ctx, a); err != nil {
			return err
		}
	}
	// A run whose receipts are journaled but not acknowledged is finished and re-sent,
	// as after a restart, so it never stays open until a reconnect (PR Reviewer Guide on #16).
	if r := a.Run; r != nil && !r.Sent && len(r.Receipts) > 0 {
		if err := m.recover(ctx, a); err != nil {
			return err
		}
	}
	now := m.now()
	if l := a.Lease; l.Open() {
		// Expiry moves the lease to rotation_pending; then its cleanup is the only
		// rotation path and scheduled occurrences wait (§3.6 step 5).
		if l.State == LeaseActive && !now.Before(l.ExpiresAt) {
			l.State, l.NextAttemptAt, l.Mirrored = LeaseRotationPending, now, false
			// A wrap still undelivered is dropped and its expiry queued in the same save,
			// before any later lease can replace this one (security review of #16).
			if l.Delivery != nil {
				l.Delivery = nil
				a.Results = append(a.Results, TxResult{RequestID: l.RequestID, Result: ReasonLeaseExpired})
			}
			if err := m.J.Save(a); err != nil {
				return err
			}
			_ = m.mirror(ctx, a)
		}
		return m.cleanup(ctx, a)
	}
	p, _ := m.Trust.Policy(a.ID)
	if p == nil || p.AccountKind != pqcrypto.KindManaged || p.RotationSchedule == nil || a.Quarantined || a.Run.Open() ||
		now.Before(a.NextAttemptAt) || a.Refusals >= MaxRefusals {
		return nil
	}
	if a.MinAgeSeconds > p.RotationSchedule.IntervalSeconds {
		if a.HealthReason != ReasonBelowMinAge {
			setHealth(a, HealthRotationFailed, ReasonBelowMinAge)
			if err := m.J.Save(a); err != nil {
				return err
			}
			m.report(ctx, a, "")
		}
		return nil
	}
	k, at, ok := Outstanding(p.RotationSchedule, a, now)
	if !ok {
		return nil
	}
	return m.rotate(ctx, a, k, at)
}

// ReasonBelowMinAge is the rotation_failed reason when the target's minimum password age is
// longer than the schedule interval: no occurrence runs until a new policy arrives (§4.4).
const ReasonBelowMinAge = "schedule_below_min_age"

// refused records a refused scheduled attempt: the occurrence stays outstanding and the next
// attempt waits until max(last change + minimum age, now + interval) (§4.4).
func (m *Machine) refused(a *Account) {
	a.Refusals++
	next := m.now()
	if p, _ := m.Trust.Policy(a.ID); p != nil && p.RotationSchedule != nil {
		next = next.Add(time.Duration(p.RotationSchedule.IntervalSeconds) * time.Second)
	}
	if a.MinAgeDeadline.After(next) {
		next = a.MinAgeDeadline
	}
	a.NextAttemptAt = next
}

// Schedule runs Tick every interval and on every nudge until ctx ends.
func (m *Machine) Schedule(ctx context.Context, every time.Duration, nudges <-chan struct{}) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := m.Tick(ctx); err != nil && ctx.Err() == nil {
			log.Printf("[BROKER] scheduler: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-nudges:
		}
	}
}
