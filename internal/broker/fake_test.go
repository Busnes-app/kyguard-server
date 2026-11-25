package broker_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
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

// rig is a Control Plane, a paired and admitted broker with its journal, one account with
// an enrolled v1, and a fake target.
type rig struct {
	t      *testing.T
	cp     *brokertest.CP
	b      *brokertest.Broker
	dir    string
	pol    *pqcrypto.PolicyManifest
	target *fakeTarget
	alerts []string
	cpw    broker.ControlPlane // what the machine talks to
}

const initialPassword = "initial-Password-0"

func newRig(t *testing.T) *rig {
	t.Helper()
	cp := brokertest.NewCP(t)
	b := cp.PairBroker()
	cp.AdmitPool(1, b.Member(pqcrypto.StatusActive))
	if err := cp.Dial(b); err != nil {
		t.Fatal(err)
	}
	r := &rig{t: t, cp: cp, b: b, dir: t.TempDir(), target: newTarget(initialPassword)}
	r.pol = cp.Account(nil)
	j, err := broker.OpenJournal(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SavePairing(&broker.Identity{BrokerID: b.ID, Cert: b.Paired.Cert, CACert: b.Paired.CACert, ListenerURL: cp.Srv.URL, Bundle: b.Paired.Bundle, Fingerprint: cp.Dep.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	r.cpw = broker.NewChannelCP(b.Conn)
	r.seed()
	m := r.machine()
	defer m.J.Close()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

// seed puts an enrolled v1 on the Control Plane: a broker-sealed envelope of the initial
// password with commit_target and release, as a completed earlier rotation leaves it.
func (r *rig) seed() {
	t := r.t
	ctx := context.Background()
	v := r.cp.Store.Vault()
	op := pqtest.UUID()
	ver, err := v.Reserve(ctx, string(r.pol.AccountID), string(op), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pqcrypto.ObjDigest(r.pol)
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: r.cp.Dep.ID, Epoch: r.pol.Epoch, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: r.pol.AccountID}, SignerRole: pqcrypto.RoleBroker}
	e, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), pqcrypto.Counter(ver), d.Hex(), 0, time.Now(), []byte(initialPassword),
		[]pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(r.b.ID), Pub: r.b.Enc.Public().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	pqcrypto.Sign(e, pqcrypto.RoleBroker, r.b.Sig)
	ed, _ := pqcrypto.ObjDigest(e)
	if err := v.PutEnvelope(ctx, string(op), &store.StoredEnvelope{EnvelopeID: string(e.EnvelopeID), AccountID: string(r.pol.AccountID), SecretVersion: ver, EnvelopeKind: "managed", Digest: string(ed.Hex()), Envelope: pqtest.Canon(t, e)}); err != nil {
		t.Fatal(err)
	}
	var rs []*store.StoredReceipt
	prev := pqcrypto.ZeroHex
	for i, typ := range []string{pqcrypto.ReceiptCommitTarget, pqcrypto.ReceiptRelease} {
		rc := &pqcrypto.EnvelopeReceipt{Header: pqcrypto.Header{Type: pqcrypto.TypeReceipt, DeploymentID: r.cp.Dep.ID, Epoch: r.pol.Epoch, Scope: e.Scope, SignerRole: pqcrypto.RoleBroker},
			EnvelopeID: e.EnvelopeID, EnvelopeKind: e.EnvelopeKind, SecretVersion: e.SecretVersion, ReceiptSeq: pqcrypto.Counter(i + 1), PrevReceiptHash: prev,
			ReceiptType: typ, OperationID: op, ExtraRecipients: []pqcrypto.Recipient{}, IssuedAt: pqcrypto.NewTime(time.Now())}
		pqcrypto.Sign(rc, pqcrypto.RoleBroker, r.b.Sig)
		dg, _ := pqcrypto.ObjDigest(rc)
		rs = append(rs, &store.StoredReceipt{EnvelopeID: string(e.EnvelopeID), ReceiptSeq: uint64(i + 1), ReceiptType: typ, OperationID: string(op), Digest: string(dg.Hex()), PrevReceiptHash: string(prev), Receipt: pqtest.Canon(t, rc)})
		prev = dg.Hex()
	}
	if err := v.Complete(ctx, string(op), string(r.pol.AccountID), rs, string(e.EnvelopeID), "", true); err != nil {
		t.Fatal(err)
	}
}

// machine opens the broker as a fresh process would: journal, keys, trust from disk.
func (r *rig) machine() *broker.Machine {
	r.t.Helper()
	j, err := broker.OpenJournal(r.dir)
	if err != nil {
		r.t.Fatal(err)
	}
	tr, err := j.Trust()
	if err != nil {
		r.t.Fatal(err)
	}
	return &broker.Machine{J: j, Trust: tr, Keys: &broker.Keys{TLS: r.b.TLS, Sig: r.b.Sig, Enc: r.b.Enc}, ID: r.b.ID, CP: r.cpw,
		Connectors: map[string]broker.Connector{pqcrypto.ConnectorSSHPasswd: r.target}, AckTimeout: 2 * time.Second,
		Alerts: func(s string) { r.alerts = append(r.alerts, s) }}
}

func (r *rig) account(m *broker.Machine) *broker.Account {
	r.t.Helper()
	a, err := m.J.Account(r.pol.AccountID)
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

func (r *rig) cpAccount() *store.Account {
	a, err := r.cp.Store.Vault().GetAccount(context.Background(), string(r.pol.AccountID))
	if err != nil {
		r.t.Fatal(err)
	}
	return a
}

func (r *rig) cpLock() string {
	op, _, _ := r.cp.Store.Vault().Lock(context.Background(), string(r.pol.AccountID))
	return op
}

// wrapCP lets a test override single Control Plane calls.
type wrapCP struct {
	broker.ControlPlane
	intent  func(ctx context.Context, raw []byte) error
	reserve func(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error)
	sync    func(ctx context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error)
	account func(ctx context.Context, id pqcrypto.UUID, after pqcrypto.Counter, more bool) (*brokerproto.AccountState, error)
	// receiptsErr fails every receipts delivery while set.
	receiptsErr error
}

func (w *wrapCP) Receipts(ctx context.Context, op, account pqcrypto.UUID, rs []pqcrypto.B64) error {
	if w.receiptsErr != nil {
		return w.receiptsErr
	}
	return w.ControlPlane.Receipts(ctx, op, account, rs)
}

func (w *wrapCP) Intent(ctx context.Context, raw []byte) error {
	if w.intent != nil {
		return w.intent(ctx, raw)
	}
	return w.ControlPlane.Intent(ctx, raw)
}

func (w *wrapCP) Reserve(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
	if w.reserve != nil {
		return w.reserve(ctx, account, op, reported)
	}
	return w.ControlPlane.Reserve(ctx, account, op, reported)
}

func (w *wrapCP) Sync(ctx context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error) {
	if w.sync != nil {
		return w.sync(ctx, req)
	}
	return w.ControlPlane.Sync(ctx, req)
}

func (w *wrapCP) SyncAccount(ctx context.Context, id pqcrypto.UUID, after pqcrypto.Counter, more bool) (*brokerproto.AccountState, error) {
	if w.account != nil {
		return w.account(ctx, id, after, more)
	}
	return w.ControlPlane.SyncAccount(ctx, id, after, more)
}
