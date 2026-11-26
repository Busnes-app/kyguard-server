// Package brokerrig drives a real broker Machine against an in-process Control Plane for
// tests: one admitted broker, its journal, and one managed account with a current v1.
// Import it from _test.go files only.
package brokerrig

import (
	"context"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Rig is a Control Plane, a paired and admitted broker with its journal and one managed
// account whose current envelope (v1) holds Password, as an earlier rotation leaves it.
type Rig struct {
	T        *testing.T
	CP       *brokertest.CP
	B        *brokertest.Broker
	Dir      string
	Pol      *pqcrypto.PolicyManifest
	Password string
	Conn     broker.Connector
	ConnType string
	Alerts   []string
	CPW      broker.ControlPlane // what the machine talks to
}

// Options configures New.
type Options struct {
	Connector     broker.Connector
	ConnectorType string                                                                      // default ssh_passwd
	Target        func(cp *brokertest.CP, acct, asset pqcrypto.UUID) ([]byte, pqcrypto.HexID) // default: an SSH descriptor
	Password      string                                                                      // the v1 password
	NoSeed        bool                                                                        // no v1: the account awaits its first enrollment
	Edit          []func(*pqcrypto.PolicyManifest)
}

// New builds a rig and syncs the broker once.
func New(t *testing.T, o Options) *Rig {
	t.Helper()
	cp := brokertest.NewCP(t)
	b := cp.PairBroker()
	cp.AdmitPool(1, b.Member(pqcrypto.StatusActive))
	if err := cp.Dial(b); err != nil {
		t.Fatal(err)
	}
	if o.ConnectorType == "" {
		o.ConnectorType = pqcrypto.ConnectorSSHPasswd
	}
	r := &Rig{T: t, CP: cp, B: b, Dir: t.TempDir(), Password: o.Password, Conn: o.Connector, ConnType: o.ConnectorType}
	edit := func(p *pqcrypto.PolicyManifest) {
		for _, e := range o.Edit {
			e(p)
		}
	}
	if o.Target != nil {
		r.Pol = cp.AccountWith(func(acct, asset pqcrypto.UUID) ([]byte, pqcrypto.HexID) { return o.Target(cp, acct, asset) }, edit)
	} else {
		r.Pol = cp.Account(edit)
	}
	j, err := broker.OpenJournal(r.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.SavePairing(&broker.Identity{BrokerID: b.ID, Cert: b.Paired.Cert, CACert: b.Paired.CACert, ListenerURL: cp.Srv.URL, Bundle: b.Paired.Bundle, Fingerprint: cp.Dep.Fingerprint}); err != nil {
		t.Fatal(err)
	}
	j.Close()
	r.CPW = broker.NewChannelCP(b.Conn)
	if !o.NoSeed {
		r.Seed()
	}
	m := r.Machine()
	defer m.J.Close()
	if err := m.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	return r
}

// Seed puts v1 on the Control Plane: a broker-sealed envelope of the initial
// password with commit_target and release, as a completed earlier rotation leaves it.
func (r *Rig) Seed() {
	t := r.T
	ctx := context.Background()
	v := r.CP.Store.Vault()
	op := pqtest.UUID()
	ver, err := v.Reserve(ctx, string(r.Pol.AccountID), string(op), 0)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := pqcrypto.ObjDigest(r.Pol)
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: r.CP.Dep.ID, Epoch: r.Pol.Epoch, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: r.Pol.AccountID}, SignerRole: pqcrypto.RoleBroker}
	e, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), pqcrypto.Counter(ver), d.Hex(), 0, time.Now(), []byte(r.Password),
		[]pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(r.B.ID), Pub: r.B.Enc.Public().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	pqcrypto.Sign(e, pqcrypto.RoleBroker, r.B.Sig)
	ed, _ := pqcrypto.ObjDigest(e)
	if err := v.PutEnvelope(ctx, string(op), &store.StoredEnvelope{EnvelopeID: string(e.EnvelopeID), AccountID: string(r.Pol.AccountID), SecretVersion: ver, EnvelopeKind: "managed", Digest: string(ed.Hex()), Envelope: pqtest.Canon(t, e)}); err != nil {
		t.Fatal(err)
	}
	var rs []*store.StoredReceipt
	prev := pqcrypto.ZeroHex
	for i, typ := range []string{pqcrypto.ReceiptCommitTarget, pqcrypto.ReceiptRelease} {
		rc := &pqcrypto.EnvelopeReceipt{Header: pqcrypto.Header{Type: pqcrypto.TypeReceipt, DeploymentID: r.CP.Dep.ID, Epoch: r.Pol.Epoch, Scope: e.Scope, SignerRole: pqcrypto.RoleBroker},
			EnvelopeID: e.EnvelopeID, EnvelopeKind: e.EnvelopeKind, SecretVersion: e.SecretVersion, ReceiptSeq: pqcrypto.Counter(i + 1), PrevReceiptHash: prev,
			ReceiptType: typ, OperationID: op, ExtraRecipients: []pqcrypto.Recipient{}, IssuedAt: pqcrypto.NewTime(time.Now())}
		pqcrypto.Sign(rc, pqcrypto.RoleBroker, r.B.Sig)
		dg, _ := pqcrypto.ObjDigest(rc)
		rs = append(rs, &store.StoredReceipt{EnvelopeID: string(e.EnvelopeID), ReceiptSeq: uint64(i + 1), ReceiptType: typ, OperationID: string(op), Digest: string(dg.Hex()), PrevReceiptHash: string(prev), Receipt: pqtest.Canon(t, rc)})
		prev = dg.Hex()
	}
	if err := v.Complete(ctx, string(op), string(r.Pol.AccountID), rs, string(e.EnvelopeID), "", store.LockDelete); err != nil {
		t.Fatal(err)
	}
}

// Machine opens the broker as a fresh process would: journal, keys, trust from disk.
func (r *Rig) Machine() *broker.Machine {
	r.T.Helper()
	j, err := broker.OpenJournal(r.Dir)
	if err != nil {
		r.T.Fatal(err)
	}
	tr, err := j.Trust()
	if err != nil {
		r.T.Fatal(err)
	}
	return &broker.Machine{J: j, Trust: tr, Keys: &broker.Keys{TLS: r.B.TLS, Sig: r.B.Sig, Enc: r.B.Enc}, ID: r.B.ID, CP: r.CPW,
		Connectors: map[string]broker.Connector{r.ConnType: r.Conn}, AckTimeout: 2 * time.Second,
		Alerts: func(s string) { r.Alerts = append(r.Alerts, s) }}
}

// Account reads the broker journal record of the rig account.
func (r *Rig) Account(m *broker.Machine) *broker.Account {
	r.T.Helper()
	a, err := m.J.Account(r.Pol.AccountID)
	if err != nil {
		r.T.Fatal(err)
	}
	return a
}

// CPAccount reads the Control Plane row of the rig account.
func (r *Rig) CPAccount() *store.Account {
	a, err := r.CP.Store.Vault().GetAccount(context.Background(), string(r.Pol.AccountID))
	if err != nil {
		r.T.Fatal(err)
	}
	return a
}

// CPLock is the operation holding the rig account's lock, or "".
func (r *Rig) CPLock() string {
	op, _, _ := r.CP.Store.Vault().Lock(context.Background(), string(r.Pol.AccountID))
	return op
}

// WrapCP lets a test override single Control Plane calls.
type WrapCP struct {
	broker.ControlPlane
	OnIntent  func(ctx context.Context, raw []byte) error
	OnReserve func(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error)
	OnSync    func(ctx context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error)
	OnAccount func(ctx context.Context, id pqcrypto.UUID, after, from pqcrypto.Counter) (*brokerproto.AccountState, error)
	// ReceiptsErr fails every receipts delivery while set; StatusErr every status report.
	ReceiptsErr, StatusErr error
	// LeaseErr and DeliveryErr fail every lease mirror or checkout delivery while set.
	LeaseErr, DeliveryErr error
}

func (w *WrapCP) Status(ctx context.Context, s brokerproto.StatusRequest) error {
	if w.StatusErr != nil {
		return w.StatusErr
	}
	return w.ControlPlane.Status(ctx, s)
}

func (w *WrapCP) Lease(ctx context.Context, r brokerproto.LeaseRequest) error {
	if w.LeaseErr != nil {
		return w.LeaseErr
	}
	return w.ControlPlane.Lease(ctx, r)
}

func (w *WrapCP) Delivery(ctx context.Context, r brokerproto.DeliveryRequest) error {
	if w.DeliveryErr != nil {
		return w.DeliveryErr
	}
	return w.ControlPlane.Delivery(ctx, r)
}

func (w *WrapCP) Intent(ctx context.Context, raw []byte) error {
	if w.OnIntent != nil {
		return w.OnIntent(ctx, raw)
	}
	return w.ControlPlane.Intent(ctx, raw)
}

func (w *WrapCP) Reserve(ctx context.Context, account, op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
	if w.OnReserve != nil {
		return w.OnReserve(ctx, account, op, reported)
	}
	return w.ControlPlane.Reserve(ctx, account, op, reported)
}

func (w *WrapCP) Sync(ctx context.Context, req brokerproto.SyncRequest) (*brokerproto.SyncReply, error) {
	if w.OnSync != nil {
		return w.OnSync(ctx, req)
	}
	return w.ControlPlane.Sync(ctx, req)
}

func (w *WrapCP) SyncAccount(ctx context.Context, id pqcrypto.UUID, after, from pqcrypto.Counter) (*brokerproto.AccountState, error) {
	if w.OnAccount != nil {
		return w.OnAccount(ctx, id, after, from)
	}
	return w.ControlPlane.SyncAccount(ctx, id, after, from)
}

func (w *WrapCP) Receipts(ctx context.Context, op, account pqcrypto.UUID, rs []pqcrypto.B64) error {
	if w.ReceiptsErr != nil {
		return w.ReceiptsErr
	}
	return w.ControlPlane.Receipts(ctx, op, account, rs)
}
