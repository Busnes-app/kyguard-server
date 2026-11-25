package broker_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/broker/brokerrig"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// fakeTarget is one account on a target, as an ssh_passwd connector sees it.
type fakeTarget struct {
	mu       sync.Mutex
	password string
	changed  int // pwdLastSet stand-in
	writes   int // changes that reached the target
	logins   map[string]int
	failed   int      // denied logins
	hosts    []string // descriptor hosts logged into
	// Faults.
	refuseBeforeCommit bool  // e.g. an unrecognized prompt
	refuseAfterCommit  bool  // e.g. password policy
	ambiguous          error // returned after commit
	applyAmbiguous     bool  // whether the ambiguous write took effect
	// Reported by PasswordAge.
	lastChange time.Time
	minAge     time.Duration
}

func newTarget(pw string) *fakeTarget { return &fakeTarget{password: pw, logins: map[string]int{}} }

func (f *fakeTarget) login(pw []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins[string(pw)]++
	if string(pw) != f.password {
		f.failed++
		return broker.ErrAuthFailed
	}
	return nil
}

func (f *fakeTarget) Login(_ context.Context, d *pqcrypto.TargetDescriptor, pw []byte) (broker.Session, error) {
	f.mu.Lock()
	f.hosts = append(f.hosts, d.Endpoint.Host)
	f.mu.Unlock()
	if err := f.login(pw); err != nil {
		return nil, err
	}
	return &fakeSession{f}, nil
}

func (f *fakeTarget) Verify(_ context.Context, d *pqcrypto.TargetDescriptor, pw []byte, baseline string) error {
	f.mu.Lock()
	f.hosts = append(f.hosts, d.Endpoint.Host)
	f.mu.Unlock()
	if err := f.login(pw); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strconv.Itoa(f.changed) == baseline {
		return errors.New("pwdLastSet did not advance")
	}
	return nil
}

func (f *fakeTarget) state() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.password, f.writes
}

type fakeSession struct{ f *fakeTarget }

func (s *fakeSession) Baseline(context.Context) (string, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	return strconv.Itoa(s.f.changed), nil
}

func (s *fakeSession) Change(_ context.Context, _, pNew []byte, commit func() error) error {
	if s.f.refuseBeforeCommit {
		return broker.ErrRefused
	}
	if err := commit(); err != nil {
		return err
	}
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	switch {
	case s.f.refuseAfterCommit:
		return broker.ErrRefused
	case s.f.ambiguous != nil:
		if s.f.applyAmbiguous {
			s.f.password, s.f.changed, s.f.writes = string(pNew), s.f.changed+1, s.f.writes+1
		}
		return s.f.ambiguous
	}
	s.f.password, s.f.changed, s.f.writes = string(pNew), s.f.changed+1, s.f.writes+1
	return nil
}

func (s *fakeSession) Close() error { return nil }

func (s *fakeSession) PasswordAge(context.Context) (time.Time, time.Duration, error) {
	s.f.mu.Lock()
	defer s.f.mu.Unlock()
	return s.f.lastChange, s.f.minAge, nil
}

const initialPassword = "initial-Password-0"

// rig is a brokerrig.Rig over a fake target.
type rig struct {
	*brokerrig.Rig
	target *fakeTarget
	pol    *pqcrypto.PolicyManifest
	cp     *brokertest.CP
}

func newRig(t *testing.T, edit ...func(*pqcrypto.PolicyManifest)) *rig {
	t.Helper()
	return newRigWith(t, false, edit...)
}

func newRigWith(t *testing.T, noSeed bool, edit ...func(*pqcrypto.PolicyManifest)) *rig {
	t.Helper()
	tg := newTarget(initialPassword)
	r := brokerrig.New(t, brokerrig.Options{Connector: tg, Password: initialPassword, NoSeed: noSeed, Edit: edit})
	return &rig{Rig: r, target: tg, pol: r.Pol, cp: r.CP}
}

func (r *rig) machine() *broker.Machine                  { return r.Machine() }
func (r *rig) account(m *broker.Machine) *broker.Account { return r.Account(m) }
func (r *rig) cpAccount() *store.Account                 { return r.CPAccount() }
func (r *rig) cpLock() string                            { return r.CPLock() }
