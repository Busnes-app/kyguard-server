package brokerproto_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
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
	// A late retry of the finished reservation takes no version and no lock (PR Reviewer
	// Guide on #10).
	if again, err := f.reserve(op, 0); !remote(err, "conflict") {
		t.Fatalf("retry after completion: %v %v", again, err)
	}
	if lock, _, _ := f.cp.Store.Vault().Lock(ctx, string(f.acct())); lock != "" {
		t.Fatalf("a finished operation took the lock again: %s", lock)
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
		last = s.AccountsNext
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
	// The broker already holds the current chain; only newer history is missing.
	got, pages := syncAll(t, f, v)
	if len(got) != 13 || pages < 2 {
		t.Fatalf("%d chains in %d pages", len(got), pages)
	}
}

// syncAll pages one account's sync from after and fails if any reply with more than one
// chain is over SyncBudget. It returns the envelopes received and the page count.
func syncAll(t *testing.T, f *vaultFixture, after pqcrypto.Counter) (map[string]bool, int) {
	t.Helper()
	got, pages, from := map[string]bool{}, 0, pqcrypto.Counter(0)
	for {
		if pages > 40 {
			t.Fatal("sync never completes")
		}
		var st brokerproto.AccountState
		if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: f.acct(), AfterVersion: after, From: from}, &st); err != nil {
			t.Fatal(err)
		}
		pages++
		size := (len(st.Descriptor) + 2) / 3 * 4
		for _, c := range st.Chains {
			got[string(c.Envelope)] = true
			size += (len(c.Envelope) + 2) / 3 * 4
			for _, r := range c.Receipts {
				size += (len(r) + 2) / 3 * 4
			}
			var v struct {
				V pqcrypto.Counter `json:"secret_version"`
			}
			json.Unmarshal(c.Envelope, &v)
			from = max(from, v.V)
		}
		if len(st.Chains) > 1 && size > brokerproto.SyncBudget {
			t.Fatalf("page %d: %d chains, %d encoded bytes over a %d budget", pages, len(st.Chains), size, brokerproto.SyncBudget)
		}
		if !st.More {
			return got, pages
		}
		if len(st.Chains) == 0 {
			t.Fatal("a page with more carries no chain")
		}
	}
}

// Open chains count against the reply budget like any other and are paged too: several
// unterminated chains at or below the broker's version, each one admissible but together
// over the budget, arrive across replies (security review of #10).
func TestOpenChainsArePagedWithinTheBudget(t *testing.T) {
	f := newVault(t)
	saved := brokerproto.SyncBudget
	defer func() { brokerproto.SyncBudget = saved }()
	v := f.cp.Store.Vault()
	ctx := context.Background()
	var top pqcrypto.Counter
	var raw []byte
	for range 6 { // unterminated candidates whose locks were released
		op := pqtest.UUID()
		ver, err := f.reserve(op, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, raw = f.envelope(ver)
		if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
			t.Fatal(err)
		}
		if err := v.Complete(ctx, string(op), string(f.acct()), nil, "", "", true); err != nil {
			t.Fatal(err)
		}
		top = ver
	}
	brokerproto.SyncBudget = (len(raw)+2)/3*4*2 + 64 // two envelopes fit, three do not
	got, pages := syncAll(t, f, top)
	if len(got) != 6 || pages < 3 {
		t.Fatalf("%d open chains in %d pages", len(got), pages)
	}
}

// Manifest pages are bounded by SyncBudget in encoded bytes, not only by count, and always
// carry one manifest so a page of large manifests never repeats forever (PR Reviewer Guide
// on #10).
func TestManifestPagesAreBudgeted(t *testing.T) {
	f := newVault(t)
	saved := brokerproto.SyncBudget
	defer func() { brokerproto.SyncBudget = saved }()
	for range 9 {
		f.cp.Account(nil)
	}
	ms, err := f.cp.Store.Guard().Manifests(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	brokerproto.SyncBudget = len(ms[len(ms)-1].Manifest) * 3 // under four policies
	after, pages := 0, 0
	for {
		if pages > len(ms)+2 {
			t.Fatal("sync never completes")
		}
		var s brokerproto.SyncReply
		if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: after}, &s); err != nil {
			t.Fatal(err)
		}
		pages++
		size := 0
		for _, m := range s.Manifests {
			size += (len(m) + 2) / 3 * 4
		}
		if len(s.Manifests) > 1 && size > brokerproto.SyncBudget {
			t.Fatalf("page of %d manifests, %d encoded bytes over a %d budget", len(s.Manifests), size, brokerproto.SyncBudget)
		}
		after += len(s.Manifests)
		if len(s.Manifests) == 0 {
			break
		}
	}
	if after != len(ms) || pages < 4 {
		t.Fatalf("%d of %d manifests in %d pages", after, len(ms), pages)
	}
	// A budget below one manifest still advances one manifest per page.
	brokerproto.SyncBudget = 1
	var s brokerproto.SyncReply
	if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{}, &s); err != nil || len(s.Manifests) != 1 {
		t.Fatalf("tiny budget: %d manifests, %v", len(s.Manifests), err)
	}
}

// countingStore counts the chains the listener reads from the store.
type countingStore struct {
	store.Store
	n *atomic.Int64
}

func (s countingStore) Vault() store.VaultStore { return countingVault{s.Store.Vault(), s.n} }

func (s countingStore) Guard() store.GuardStore { return countingGuard{s.Store.Guard(), s.n} }

type countingGuard struct {
	store.GuardStore
	n *atomic.Int64
}

func (g countingGuard) Manifests(ctx context.Context, after int64) ([]*store.TrustManifest, error) {
	ms, err := g.GuardStore.Manifests(ctx, after)
	g.n.Add(int64(len(ms)))
	return ms, err
}

func (g countingGuard) ManifestsPage(ctx context.Context, after int64, limit int) ([]*store.TrustManifest, error) {
	ms, err := g.GuardStore.ManifestsPage(ctx, after, limit)
	g.n.Add(int64(len(ms)))
	return ms, err
}

// A manifest sync page reads at most SyncPage manifests from the store, however long the
// trust history (security review of #10).
func TestManifestSyncReadsOnlyOnePage(t *testing.T) {
	f := newVault(t)
	for range brokerproto.SyncPage + 10 {
		f.cp.Account(nil)
	}
	var n atomic.Int64
	f.cp.L.Store = countingStore{f.cp.Store, &n}
	after := 0
	for pages := 0; ; pages++ {
		if pages > 10 {
			t.Fatal("sync never completes")
		}
		n.Store(0)
		var s brokerproto.SyncReply
		if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: after}, &s); err != nil {
			t.Fatal(err)
		}
		if read := n.Load(); read > int64(brokerproto.SyncPage) {
			t.Fatalf("a sync page read %d manifests", read)
		}
		if len(s.Manifests) == 0 {
			return
		}
		after += len(s.Manifests)
	}
}

type countingVault struct {
	store.VaultStore
	n *atomic.Int64
}

func (v countingVault) count(cs []*store.StoredChain, err error) ([]*store.StoredChain, error) {
	v.n.Add(int64(len(cs)))
	return cs, err
}

func (v countingVault) Chains(ctx context.Context, a string) ([]*store.StoredChain, error) {
	return v.count(v.VaultStore.Chains(ctx, a))
}

func (v countingVault) ChainsAfter(ctx context.Context, a string, after uint64, limit int) ([]*store.StoredChain, error) {
	return v.count(v.VaultStore.ChainsAfter(ctx, a, after, limit))
}

func (v countingVault) OpenChains(ctx context.Context, a string, after, upTo uint64, limit int) ([]*store.StoredChain, error) {
	return v.count(v.VaultStore.OpenChains(ctx, a, after, upTo, limit))
}

func (v countingVault) Chain(ctx context.Context, a, e string) (*store.StoredChain, error) {
	c, err := v.VaultStore.Chain(ctx, a, e)
	if err == nil {
		v.n.Add(1)
	}
	return c, err
}

// Paging bounds the store reads, not only the reply: an account sync page reads at most
// SyncChains+1 chains, open or newer, and a receipts request reads only the chain
// it names, however long the history (PR Reviewer Guide on #10).
func TestAccountSyncAndReceiptsReadOnlyWhatTheyNeed(t *testing.T) {
	f := newVault(t)
	saved := brokerproto.SyncChains
	defer func() { brokerproto.SyncChains = saved }()
	brokerproto.SyncChains = 2
	rotate := func(end string) {
		op := pqtest.UUID()
		v, _ := f.reserve(op, 0)
		e, raw := f.envelope(v)
		if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
			t.Fatal(err)
		}
		var rs []pqcrypto.B64
		if end == pqcrypto.ReceiptAbort {
			ab, _ := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRefused, op)
			rs = append(rs, ab)
		} else {
			c1, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
			c2, _ := f.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", op)
			rs = append(rs, c1, c2)
		}
		if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: rs}, nil); err != nil {
			t.Fatal(err)
		}
	}
	rotate(pqcrypto.ReceiptRelease)
	for range 12 {
		rotate(pqcrypto.ReceiptAbort)
	}
	var n atomic.Int64
	f.cp.L.Store = countingStore{f.cp.Store, &n} // the next frame orders this write before the listener's reads
	after, pages, got := pqcrypto.Counter(0), 0, 0
	for {
		if pages > 20 {
			t.Fatal("sync never completes")
		}
		n.Store(0)
		var st brokerproto.AccountState
		if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: f.acct(), From: after}, &st); err != nil {
			t.Fatal(err)
		}
		pages++
		if read := n.Load(); read > int64(brokerproto.SyncChains)+1 {
			t.Fatalf("page %d read %d chains for %d sent", pages, read, len(st.Chains))
		}
		got += len(st.Chains)
		for _, c := range st.Chains {
			var v struct {
				V pqcrypto.Counter `json:"secret_version"`
			}
			json.Unmarshal(c.Envelope, &v)
			after = max(after, v.V)
		}
		if !st.More {
			break
		}
	}
	if got != 13 || pages < 6 {
		t.Fatalf("%d chains in %d pages", got, pages)
	}
	n.Store(0)
	rotate(pqcrypto.ReceiptRelease)
	if read := n.Load(); read != 1 {
		t.Fatalf("a receipts request read %d chains", read)
	}
}

// Pushes the broker has not drained never stall the channel reader: a call still gets its
// result (PR Reviewer Guide on #10).
func TestUndrainedPushesNeverBlockResults(t *testing.T) {
	f := newVault(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for range cap(f.b.Conn.Pushes) + 8 {
		if err := f.cp.L.Send(ctx, f.b.ID, brokerproto.Message{V: 1, Type: brokerproto.MsgNudge}); err != nil {
			t.Fatal(err)
		}
	}
	var s brokerproto.SyncReply
	if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{}, &s); err != nil {
		t.Fatalf("call behind a full push queue: %v", err)
	}
	if n := len(f.b.Conn.Pushes); n != cap(f.b.Conn.Pushes) {
		t.Fatalf("%d pushes queued", n)
	}
}

// §4.2: a delayed write_outcome_unknown status moves only a mutating run; it never undoes
// an outcome the receipts recorded.
func TestLateUnknownStatusNeverRegressesARun(t *testing.T) {
	f := newVault(t)
	ctx := context.Background()
	state := func(op pqcrypto.UUID) string {
		t.Helper()
		run, err := f.cp.Store.Vault().GetRun(ctx, string(f.acct()), string(op))
		if err != nil {
			t.Fatal(err)
		}
		return run.State
	}
	unknown := func(op pqcrypto.UUID) {
		t.Helper()
		req := brokerproto.StatusRequest{AccountID: f.acct(), Health: "unknown", OperationID: op, RunState: "write_outcome_unknown"}
		if err := f.call(brokerproto.MsgStatus, req, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"target_verified", "release_authorized", "aborted"} {
		op := pqtest.UUID()
		v, err := f.reserve(op, 0)
		if err != nil {
			t.Fatal(err)
		}
		e, raw := f.envelope(v)
		if err := f.call(brokerproto.MsgEnvelope, brokerproto.EnvelopeRequest{OperationID: op, Envelope: raw}, nil); err != nil {
			t.Fatal(err)
		}
		if err := f.intent(op, v, e.EnvelopeID); err != nil {
			t.Fatal(err)
		}
		unknown(op)
		if s := state(op); s != "write_outcome_unknown" {
			t.Fatalf("mutating run after unknown status: %s", s)
		}
		c1, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
		c2, _ := f.receipt(e, 2, h1, pqcrypto.ReceiptRelease, "", op)
		a, _ := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptAbort, pqcrypto.ReasonRefused, op)
		rs := map[string][]pqcrypto.B64{"target_verified": {c1}, "release_authorized": {c1, c2}, "aborted": {a}}[want]
		if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: rs}, nil); err != nil {
			t.Fatal(err)
		}
		if s := state(op); s != want {
			t.Fatalf("run %s, want %s", s, want)
		}
		unknown(op)
		if s := state(op); s != want {
			t.Fatalf("late unknown status moved a %s run to %s", want, s)
		}
		if want == "target_verified" { // free the lock for the next case
			if err := f.call(brokerproto.MsgReceipts, brokerproto.ReceiptsRequest{OperationID: op, AccountID: f.acct(), Receipts: []pqcrypto.B64{c1, c2}}, nil); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type accountCounter struct {
	store.Store
	rows, gets *atomic.Int64
}

func (s accountCounter) Vault() store.VaultStore {
	return accountVault{s.Store.Vault(), s.rows, s.gets}
}

type accountVault struct {
	store.VaultStore
	rows, gets *atomic.Int64
}

func (v accountVault) PoolAccounts(ctx context.Context, pool, after string, limit int) ([]*store.Account, error) {
	as, err := v.VaultStore.PoolAccounts(ctx, pool, after, limit)
	v.rows.Add(int64(len(as)))
	return as, err
}

func (v accountVault) GetAccount(ctx context.Context, id string) (*store.Account, error) {
	v.gets.Add(1)
	return v.VaultStore.GetAccount(ctx, id)
}

// An account sync page reads at most SyncAccountsPage rows, eligible or not, checks them as
// read with no query per account, and continues past the ones filtered out (PR Reviewer
// Guide on #10).
func TestAccountListReadsOnlyOnePage(t *testing.T) {
	f := newVault(t)
	saved := brokerproto.SyncAccountsPage
	defer func() { brokerproto.SyncAccountsPage = saved }()
	brokerproto.SyncAccountsPage = 2
	for range 6 {
		f.cp.Account(nil)
	}
	ctx := context.Background()
	for range 5 { // in the pool, with no admitted policy: never listed
		acct, asset := pqtest.UUID(), pqtest.UUID()
		if err := f.cp.Store.Vault().CreateAsset(ctx, &store.Asset{ID: string(asset), Name: "host"}); err != nil {
			t.Fatal(err)
		}
		if err := f.cp.Store.Vault().CreateAccount(ctx, &store.Account{ID: string(acct), AssetID: string(asset), Name: "svc", AccountKind: pqcrypto.KindManaged, PoolID: string(f.cp.Pool)}); err != nil {
			t.Fatal(err)
		}
	}
	var s brokerproto.SyncReply
	for after := 0; ; after += len(s.Manifests) {
		if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: after}, &s); err != nil {
			t.Fatal(err)
		}
		if len(s.Manifests) == 0 {
			break
		}
	}
	var rows, gets atomic.Int64
	f.cp.L.Store = accountCounter{f.cp.Store, &rows, &gets}
	var next pqcrypto.UUID
	seen := map[pqcrypto.UUID]bool{}
	pages := 0
	for ; ; pages++ {
		if pages > 20 {
			t.Fatal("sync never completes")
		}
		rows.Store(0)
		if err := f.call(brokerproto.MsgSync, brokerproto.SyncRequest{ManifestsAfter: 1 << 20, AccountsAfter: next}, &s); err != nil {
			t.Fatal(err)
		}
		if r := rows.Load(); r > int64(brokerproto.SyncAccountsPage) {
			t.Fatalf("a sync page read %d account rows", r)
		}
		for _, a := range s.Accounts {
			seen[a] = true
		}
		if s.Done {
			break
		}
		next = s.AccountsNext
	}
	if len(seen) != 7 || gets.Load() != 0 || pages < 5 {
		t.Fatalf("%d accounts in %d pages, %d per-account reads", len(seen), pages+1, gets.Load())
	}
}

// An account whose policy names a descriptor the store cannot return is an error, never a
// state without its descriptor (PR Reviewer Guide on #10).
func TestAccountSyncNeedsTheDescriptor(t *testing.T) {
	f := newVault(t)
	pol := f.cp.Account(func(p *pqcrypto.PolicyManifest) { p.TargetDescriptorDigest = pqcrypto.HexID(strings.Repeat("cd", 32)) })
	var st brokerproto.AccountState
	if err := f.call(brokerproto.MsgSyncAccount, brokerproto.SyncAccountRequest{AccountID: pol.AccountID}, &st); err == nil {
		t.Fatalf("sync without the descriptor: %+v", st)
	}
}

// The chain room the store keeps above MaxEnvelope fits commit_target plus a release with a
// wrap for every standing recipient a policy may name, so every admitted envelope can
// finish its rotation and release its lock (security review of #10).
func TestChainRoomFitsTheLargestRelease(t *testing.T) {
	f := newVault(t)
	op := pqtest.UUID()
	e, _ := f.envelope(1)
	ct, h1 := f.receipt(e, 1, pqcrypto.ZeroHex, pqcrypto.ReceiptCommitTarget, "", op)
	dek := make([]byte, pqcrypto.DEKBytes)
	var wraps []pqcrypto.Recipient
	for range pqcrypto.MaxStandingRecipients {
		k, err := recoverykey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		w, err := e.WrapTo(dek, pqtest.UUID(), k.Public().Bytes())
		if err != nil {
			t.Fatal(err)
		}
		wraps = append(wraps, w)
	}
	r := &pqcrypto.EnvelopeReceipt{Header: pqcrypto.Header{Type: pqcrypto.TypeReceipt, DeploymentID: f.cp.Dep.ID, Epoch: f.pol.Epoch,
		Scope: e.Scope, SignerRole: pqcrypto.RoleBroker}, EnvelopeID: e.EnvelopeID, EnvelopeKind: e.EnvelopeKind,
		SecretVersion: e.SecretVersion, ReceiptSeq: 2, PrevReceiptHash: h1, ReceiptType: pqcrypto.ReceiptRelease,
		OperationID: op, ExtraRecipients: wraps, IssuedAt: pqcrypto.NewTime(time.Now())}
	rel := f.signed(r)
	if room := store.MaxChain - store.MaxEnvelope; len(ct)+len(rel) > room {
		t.Fatalf("commit_target %d + release %d bytes > %d bytes of room", len(ct), len(rel), room)
	}
}

// A policy naming more standing recipients than a release can carry is refused.
func TestPolicyStandingRecipientsAreBounded(t *testing.T) {
	d := pqtest.New(t)
	p := d.ManagedPolicy(pqtest.UUID(), pqtest.UUID(), 1, pqcrypto.HexID(strings.Repeat("ab", 32)))
	p.CheckoutMode = pqcrypto.ModeStanding
	for range pqcrypto.MaxStandingRecipients + 1 {
		p.StandingRecipientPrincipalIDs = append(p.StandingRecipientPrincipalIDs, pqtest.UUID())
	}
	if _, err := d.Trust(t).Accept(d.Signed(t, p)); !errors.Is(err, pqcrypto.ErrBody) {
		t.Fatalf("policy with %d standing recipients: %v", len(p.StandingRecipientPrincipalIDs), err)
	}
}
