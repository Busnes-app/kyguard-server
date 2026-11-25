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
	type due struct {
		account pqcrypto.UUID
		k       pqcrypto.Counter
		at      time.Time
	}
	var run []due
	var errs []error
	m.mu.Lock()
	accts, err := m.J.Accounts()
	if err != nil {
		m.mu.Unlock()
		return err
	}
	now := m.now()
	for _, a := range accts {
		p, _ := m.Trust.Policy(a.ID)
		if p == nil || p.AccountKind != pqcrypto.KindManaged || p.RotationSchedule == nil || a.Quarantined || a.Run.Open() ||
			now.Before(a.NextAttemptAt) || a.Refusals >= MaxRefusals {
			continue
		}
		if a.MinAgeSeconds > p.RotationSchedule.IntervalSeconds {
			if a.HealthReason != ReasonBelowMinAge {
				setHealth(a, HealthRotationFailed, ReasonBelowMinAge)
				if err := m.J.Save(a); err != nil {
					errs = append(errs, err)
				}
				m.report(ctx, a, "")
			}
			continue
		}
		if k, at, ok := Outstanding(p.RotationSchedule, a, now); ok {
			run = append(run, due{a.ID, k, at})
		}
	}
	m.mu.Unlock()
	for _, d := range run {
		if err := m.Rotate(ctx, d.account, d.k, d.at); err != nil && !errors.Is(err, ErrNotActive) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
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
