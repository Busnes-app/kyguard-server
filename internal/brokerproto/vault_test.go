package brokerproto_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
)

type vaultFixture struct {
	t   *testing.T
	cp  *brokertest.CP
	b   *brokertest.Broker
	pol *pqcrypto.PolicyManifest
}

func newVault(t *testing.T) *vaultFixture {
	cp := brokertest.NewCP(t)
	b := cp.PairBroker()
	cp.AdmitPool(1, b.Member(pqcrypto.StatusActive))
	if err := cp.Dial(b); err != nil {
		t.Fatal(err)
	}
	return &vaultFixture{t: t, cp: cp, b: b, pol: cp.Account(nil)}
}

func (f *vaultFixture) acct() pqcrypto.UUID { return f.pol.AccountID }

func (f *vaultFixture) call(typ string, req, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f.b.Conn.Call(ctx, typ, req, out)
}

func (f *vaultFixture) reserve(op pqcrypto.UUID, reported pqcrypto.Counter) (pqcrypto.Counter, error) {
	var r brokerproto.ReserveReply
	err := f.call(brokerproto.MsgReserve, brokerproto.ReserveRequest{AccountID: f.acct(), OperationID: op, Reported: reported}, &r)
	return r.SecretVersion, err
}

// envelope seals a rotation envelope to the broker and signs it as the broker.
func (f *vaultFixture) envelope(version pqcrypto.Counter) (*pqcrypto.SecretEnvelope, []byte) {
	f.t.Helper()
	d, err := pqcrypto.ObjDigest(f.pol)
	if err != nil {
		f.t.Fatal(err)
	}
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: f.cp.Dep.ID, Epoch: f.pol.Epoch,
		Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: f.acct()}, SignerRole: pqcrypto.RoleBroker}
	e, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), version, d.Hex(), 0, time.Now(), []byte("P-new"),
		[]pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(f.b.ID), Pub: f.b.Enc.Public().Bytes()}})
	if err != nil {
		f.t.Fatal(err)
	}
	return e, f.signed(e)
}

func (f *vaultFixture) signed(o pqcrypto.Signed) []byte {
	f.t.Helper()
	if err := pqcrypto.Sign(o, pqcrypto.RoleBroker, f.b.Sig); err != nil {
		f.t.Fatal(err)
	}
	return pqtest.Canon(f.t, o)
}

// receipt returns a broker-signed receipt and its digest.
func (f *vaultFixture) receipt(e *pqcrypto.SecretEnvelope, seq pqcrypto.Counter, prev pqcrypto.HexID, typ, reason string, op pqcrypto.UUID) ([]byte, pqcrypto.HexID) {
	f.t.Helper()
	r := &pqcrypto.EnvelopeReceipt{Header: pqcrypto.Header{Type: pqcrypto.TypeReceipt, DeploymentID: f.cp.Dep.ID, Epoch: f.pol.Epoch,
		Scope: e.Scope, SignerRole: pqcrypto.RoleBroker}, EnvelopeID: e.EnvelopeID, EnvelopeKind: e.EnvelopeKind,
		SecretVersion: e.SecretVersion, ReceiptSeq: seq, PrevReceiptHash: prev, ReceiptType: typ, Reason: reason,
		OperationID: op, ExtraRecipients: []pqcrypto.Recipient{}, IssuedAt: pqcrypto.NewTime(time.Now())}
	raw := f.signed(r)
	d, err := pqcrypto.ObjDigest(r)
	if err != nil {
		f.t.Fatal(err)
	}
	return raw, d.Hex()
}

func (f *vaultFixture) intent(op pqcrypto.UUID, version pqcrypto.Counter, newEnv pqcrypto.UUID) error {
	in := brokerproto.Intent{BrokerID: f.b.ID, OperationID: op, AccountID: f.acct(), SecretVersion: version,
		Endpoint: "db1.example.test:22", Baseline: "0", NewEnvelopeID: newEnv}
	return f.call(brokerproto.MsgIntent, brokerproto.IntentRequest{Intent: pqtest.Canon(f.t, &in)}, nil)
}

func remote(err error, code string) bool {
	var r brokerproto.RemoteError
	return errors.As(err, &r) && string(r) == code
}

// A full rotation over the channel: reserve, store the candidate, record the intent, then
// commit_target and release in one completion (§4.2, §4.3).
func TestRotationRoundTripOnTheControlPlane(t *testing.T) {
	f := newVault(t)
	ctx := context.Background()
	op := pqtest.UUID()
	v, err := f.reserve(op, 0)
	if err != nil || v != 1 {
		t.Fatalf("reserve %v %v", v, err)
	}
	if again, err := f.reserve(op, 0); err != nil || again != v {
		t.Fatalf("retry of the same reservation: %v %v", again, err)
	}
	e, raw := f.envelope(v)
	for range 2 { // the second store is a retry
		if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.intent(op, v, e.EnvelopeID); err != nil {
		t.Fatal(err)
	}
	if run, err := f.cp.Store.Vault().GetRun(ctx, string(f.acct()), string(op)); err != nil || run.State != "mutating" {
		t.Fatalf("run %v %v", run, err)
	}
	c1, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
	c2, _ := f.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", op)
	req := brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: []pqcrypto.B64{c1, c2}}
	if err := f.call(brokerproto.MsgReceipts, req, nil); err != nil {
		t.Fatal(err)
	}
	a, _ := f.cp.Store.Vault().GetAccount(ctx, string(f.acct()))
	if a.CurrentEnvelopeID != string(e.EnvelopeID) {
		t.Fatalf("current envelope %q", a.CurrentEnvelopeID)
	}
	if lock, _, _ := f.cp.Store.Vault().Lock(ctx, string(f.acct())); lock != "" {
		t.Fatalf("lock still held by %s", lock)
	}
	// §13 1A acceptance test 13: re-sending a completed rotation's result changes nothing.
	if err := f.call(brokerproto.MsgReceipts, req, nil); err != nil {
		t.Fatalf("re-send: %v", err)
	}
	chains, _ := f.cp.Store.Vault().Chains(ctx, string(f.acct()))
	if len(chains) != 1 || len(chains[0].Receipts) != 2 {
		t.Fatalf("chains after re-send: %+v", chains)
	}
	var s brokerproto.SyncReply
	if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{}, &s); err != nil || s.Done || len(s.Manifests) == 0 {
		t.Fatalf("first page %+v %v", s, err)
	}
	if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: len(s.Manifests)}, &s); err != nil {
		t.Fatal(err)
	}
	if !s.Done || len(s.Accounts) != 1 || s.Accounts[0] != f.acct() {
		t.Fatalf("sync %+v", s)
	}
	var st brokerproto.AccountState
	if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: f.acct()}, &st); err != nil {
		t.Fatal(err)
	}
	if len(st.Chains) != 1 || len(st.Chains[0].Receipts) != 2 || len(st.Descriptor) == 0 || st.HighestVersion != 1 {
		t.Fatalf("account %+v", st)
	}
	// The next reservation gets a fresh version.
	if v2, err := f.reserve(pqtest.UUID(), 0); err != nil || v2 != 2 {
		t.Fatalf("next version %v %v", v2, err)
	}
}

func TestOneLockPerAccountAndVersionsNeverGoDown(t *testing.T) {
	f := newVault(t)
	op := pqtest.UUID()
	if v, err := f.reserve(op, 41); err != nil || v != 42 {
		t.Fatalf("reported high-water mark: %v %v", v, err)
	}
	if _, err := f.reserve(pqtest.UUID(), 0); !remote(err, "locked") {
		t.Fatalf("second operation: %v", err)
	}
	// An envelope at a version other than the reservation is refused.
	_, raw := f.envelope(7)
	if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); !remote(err, "locked") {
		t.Fatalf("wrong version: %v", err)
	}
	// Abort releases the lock; the aborted version is never reused.
	e, raw := f.envelope(42)
	if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
		t.Fatal(err)
	}
	ab, _ := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRestartBeforeSend, op)
	if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: []pqcrypto.B64{ab}}, nil); err != nil {
		t.Fatal(err)
	}
	if v, err := f.reserve(pqtest.UUID(), 0); err != nil || v != 43 {
		t.Fatalf("after abort: %v %v", v, err)
	}
}

func TestReceiptAppendIsCompareAndSwap(t *testing.T) {
	f := newVault(t)
	op := pqtest.UUID()
	v, _ := f.reserve(op, 0)
	e, raw := f.envelope(v)
	if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
		t.Fatal(err)
	}
	send := func(rs ...[]byte) error {
		var b64 []pqcrypto.B64
		for _, r := range rs {
			b64 = append(b64, r)
		}
		return f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: b64}, nil)
	}
	c1, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
	if err := send(c1); err != nil {
		t.Fatal(err)
	}
	// A different receipt at seq 1 (a fork) and a release that skips the head are refused.
	fork, _ := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRefused, op)
	if err := send(fork); !remote(err, string(pqcrypto.ErrChain)) {
		t.Fatalf("fork: %v", err)
	}
	gap, _ := f.receipt(e, 2, pqcrypto.ZeroHex, pqcrypto.ReceiptRelease, "", op)
	if err := send(gap); !remote(err, string(pqcrypto.ErrChain)) {
		t.Fatalf("wrong prev: %v", err)
	}
	other, _ := f.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", pqtest.UUID())
	if err := send(other); !remote(err, "receipt names another operation") {
		t.Fatalf("other operation: %v", err)
	}
	// A receipt signed by a key outside the pool.
	stranger := brokertest.NewCP(t).PairBroker()
	f2 := *f
	f2.b = stranger
	forged, _ := f2.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", op)
	if err := send(forged); !remote(err, string(pqcrypto.ErrUnknownKey)) {
		t.Fatalf("stranger: %v", err)
	}
}

// The channel serves only accounts in the broker's pool, and only while it is active.
func TestChannelScopesWorkToTheActiveBrokersPool(t *testing.T) {
	f := newVault(t)
	// An account whose policy names another pool.
	elsewhere := f.cp.Account(func(p *pqcrypto.PolicyManifest) { p.PoolID = pqtest.UUID() })
	err := f.call(brokerproto.MsgReserve, brokerproto.ReserveRequest{AccountID: elsewhere.AccountID, OperationID: pqtest.UUID()}, nil)
	if !remote(err, "account is not in this broker's pool") {
		t.Fatalf("other pool: %v", err)
	}
	// An envelope with a user recipient on a managed account is refused (§3.5).
	d, _ := pqcrypto.ObjDigest(f.pol)
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: f.cp.Dep.ID, Epoch: 1, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: f.acct()}, SignerRole: pqcrypto.RoleBroker}
	op := pqtest.UUID()
	v, _ := f.reserve(op, 0)
	bad, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqtest.UUID(), v, d.Hex(), 0, time.Now(), []byte("x"), []pqcrypto.SealTo{
		{Type: pqcrypto.RecipientBroker, ID: string(f.b.ID), Pub: f.b.Enc.Public().Bytes()},
		{Type: pqcrypto.RecipientUser, ID: string(pqtest.UUID()), Pub: f.b.Enc.Public().Bytes()}})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: f.signed(bad)}, nil); !remote(err, string(pqcrypto.ErrRecipients)) {
		t.Fatalf("user recipient: %v", err)
	}
	// Revoked mid-connection: the next request is refused.
	f.cp.AdmitPool(2, f.b.Member(pqcrypto.StatusRevoked))
	if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{}, nil); !remote(err, "broker is not the active member of its pool") {
		t.Fatalf("revoked: %v", err)
	}
}

// Sync is paged and per account, so a long history never outgrows one frame (PR Reviewer
// Guide on #10): manifests come SyncPage at a time, and an account sends only chains above
// the broker's version plus its current and unterminated ones.
func TestSyncIsPaged(t *testing.T) {
	f := newVault(t)
	for range brokerproto.SyncPage {
		f.cp.Account(nil)
	}
	after, pages, accounts := 0, 0, 0
	var last pqcrypto.UUID
	for {
		var s brokerproto.SyncReply
		if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: after, AccountsAfter: last}, &s); err != nil {
			t.Fatal(err)
		}
		pages++
		after += len(s.Manifests)
		accounts += len(s.Accounts)
		if len(s.Accounts) > 0 {
			last = s.Accounts[len(s.Accounts)-1]
		}
		if len(s.Manifests) > brokerproto.SyncPage {
			t.Fatalf("page of %d", len(s.Manifests))
		}
		if s.Done {
			break
		}
	}
	if pages < 2 || accounts != brokerproto.SyncPage+1 {
		t.Fatalf("pages=%d accounts=%d", pages, accounts)
	}
	// v1 aborted, v2 current: a broker at version 2 gets only the current chain.
	op1 := pqtest.UUID()
	v1, _ := f.reserve(op1, 0)
	e1, raw1 := f.envelope(v1)
	f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op1, Envelope: raw1}, nil)
	ab, _ := f.receipt(e1, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRefused, op1)
	f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op1, AccountID: f.acct(), Receipts: []pqcrypto.B64{ab}}, nil)
	op2 := pqtest.UUID()
	v2, _ := f.reserve(op2, 0)
	e2, raw2 := f.envelope(v2)
	f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op2, Envelope: raw2}, nil)
	c1, h1 := f.receipt(e2, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op2)
	c2, _ := f.receipt(e2, 2, h1, pqcrypto.ReceiptRelease, "", op2)
	if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op2, AccountID: f.acct(), Receipts: []pqcrypto.B64{c1, c2}}, nil); err != nil {
		t.Fatal(err)
	}
	for after, want := range map[pqcrypto.Counter]int{0: 2, 2: 1} {
		var st brokerproto.AccountState
		if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: f.acct(), AfterVersion: after}, &st); err != nil {
			t.Fatal(err)
		}
		if len(st.Chains) != want {
			t.Fatalf("after %d: %d chains, want %d", after, len(st.Chains), want)
		}
	}
}

// An account's history is sent within SyncBudget per reply, continued by version, until
// all of it arrived (security review of #10).
func TestAccountSyncIsBudgeted(t *testing.T) {
	f := newVault(t)
	saved := brokerproto.SyncBudget
	defer func() { brokerproto.SyncBudget = saved }()
	// A current chain at the start of history that, with any newer chain, exceeds the
	// budget: every continuation must still advance (security review of #10).
	op := pqtest.UUID()
	v, _ := f.reserve(op, 0)
	e, raw := f.envelope(v)
	f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil)
	c1, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
	c2, _ := f.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", op)
	if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: []pqcrypto.B64{c1, c2}}, nil); err != nil {
		t.Fatal(err)
	}
	for range 12 { // twelve refused rotations: terminated, each a few KiB
		op := pqtest.UUID()
		v, _ := f.reserve(op, 0)
		e, raw := f.envelope(v)
		f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil)
		ab, _ := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRefused, op)
		if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: []pqcrypto.B64{ab}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	brokerproto.SyncBudget = len(raw) * 2 // one chain fits, two do not
	got, pages := map[string]bool{}, 0
	after := v // the broker already holds the current chain; only newer history is missing
	for {
		if pages > 30 {
			t.Fatal("sync never completes")
		}
		var st brokerproto.AccountState
		if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: f.acct(), AfterVersion: after, Continue: pages > 0}, &st); err != nil {
			t.Fatal(err)
		}
		pages++
		size := 0
		for _, c := range st.Chains {
			got[string(c.Envelope)] = true
			size += len(c.Envelope)
			var v struct {
				V pqcrypto.Counter `json:"secret_version"`
			}
			json.Unmarshal(c.Envelope, &v)
			after = max(after, v.V)
		}
		if size*4/3 > brokerproto.SyncBudget+8<<10 {
			t.Fatalf("page of %d bytes over a %d budget", size, brokerproto.SyncBudget)
		}
		if !st.More {
			break
		}
	}
	if len(got) != 13 || pages < 2 {
		t.Fatalf("%d chains in %d pages", len(got), pages)
	}
}
