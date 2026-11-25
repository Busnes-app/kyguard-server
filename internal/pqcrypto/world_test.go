package pqcrypto

// A fixed deployment for the contract vectors: three custodians (M=2), a recovery key, a
// pool whose first broker was revoked and replaced, five principals and three accounts.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

const (
	wDeployment = "0190b2a4-1111-7111-8111-000000000001"
	wPool       = "0190b2a4-2222-7222-8222-000000000001"
	wAcctE      = "0190b2a4-3333-7333-8333-00000000000e" // managed, ephemeral, escrow on
	wAcctS      = "0190b2a4-3333-7333-8333-000000000005" // managed, standing, auto release
	wAcctV      = "0190b2a4-3333-7333-8333-00000000000f" // vaulted, escrow on
	wAsset      = "0190b2a4-4444-7444-8444-000000000001"
)

var wT0 = time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)

type wPrincipal struct {
	id  UUID
	sig *SigningKey
	enc recoverykey.PrivateKey
}

func (p *wPrincipal) encID() HexID { return HexID(p.enc.Public().ID()) }

type wBroker struct {
	id   UUID
	sig  *SigningKey
	enc  recoverykey.PrivateKey
	cert HexID
}

type world struct {
	t         *testing.T
	cust      []*SigningKey
	custIDs   []UUID
	recovery  recoverykey.PrivateKey
	bundle    []byte
	fp        HexID
	users     map[string]*wPrincipal
	old, brkA *wBroker
	context   [][]byte // manifests after the bundle, in acceptance order
	target    []byte
	targetD   HexID
	pol       map[UUID]*PolicyManifest
	polRaw    map[UUID][]byte
	trust     *Trust
}

func uuidN(prefix string, n int) UUID {
	return UUID(prefix + hex.EncodeToString([]byte{byte(n >> 8), byte(n)}))
}

func hexOf(label string) HexID {
	s := sha256.Sum256([]byte(label))
	return HexID(hex.EncodeToString(s[:]))
}

// raw returns the canonical JSON of v.
func (w *world) raw(v any) []byte {
	w.t.Helper()
	b, err := canonical.Marshal(v)
	if err != nil {
		w.t.Fatal(err)
	}
	return b
}

// signed signs o with each key in role and returns its canonical JSON.
func (w *world) signed(o Signed, role string, keys ...*SigningKey) []byte {
	w.t.Helper()
	for _, k := range keys {
		if err := Sign(o, role, k); err != nil {
			w.t.Fatal(err)
		}
	}
	return w.raw(o)
}

func (w *world) hdr(typ, kind string, scope UUID, epoch Counter, role string) Header {
	return Header{typ, wDeployment, epoch, Scope{kind, scope}, role}
}

// custodianSet builds a set over keys with threshold m.
func (w *world) custodianSet(epoch Counter, m int, keys []*SigningKey, ids []UUID) *CustodianSetManifest {
	cs := &CustodianSetManifest{Header: w.hdr(TypeCustodianSet, ScopeDeployment, wDeployment, epoch, RoleCustodian), Threshold: m}
	for i, k := range keys {
		cs.Custodians = append(cs.Custodians, Custodian{ids[i], k.Public()})
	}
	return cs
}

func (w *world) recoveryManifest(epoch Counter, escrowDefault bool) *RecoveryKeyManifest {
	return &RecoveryKeyManifest{Header: w.hdr(TypeRecoveryKey, ScopeDeployment, wDeployment, epoch, RoleCustodian),
		RecoveryKeyID: HexID(w.recovery.Public().ID()), RecoveryPubkey: w.recovery.Public().Bytes(),
		Threshold: 2, TotalShares: 3, EscrowDefaultEnabled: escrowDefault}
}

func (w *world) enrollment(p *wPrincipal, epoch Counter) *KeyEnrollmentManifest {
	sid, _ := p.sig.Public().SigKeyID()
	return &KeyEnrollmentManifest{Header: w.hdr(TypeKeyEnrollment, ScopePrincipal, p.id, epoch, RoleCustodian),
		PrincipalID: p.id, Issuer: "https://idp.example.test", Subject: "sub-" + string(p.id[len(p.id)-4:]),
		Keys: []EnrolledKey{{p.enc.Public().Bytes(), p.encID(), p.sig.Public(), sid, StatusActive}}}
}

func (w *world) member(b *wBroker, status string) BrokerMember {
	return BrokerMember{b.id, b.enc.Public().Bytes(), b.sig.Public(), b.cert, status}
}

func (w *world) pool(epoch Counter, members []BrokerMember, decom []Decommission) *BrokerPoolManifest {
	if decom == nil {
		decom = []Decommission{}
	}
	return &BrokerPoolManifest{Header: w.hdr(TypePool, ScopePool, wPool, epoch, RoleCustodian), PoolID: wPool, Members: members, DecommissionedBrokerIDs: decom}
}

func boolp(b bool) *bool { return &b }

func (w *world) managedPolicy(acct UUID, epoch Counter, mode string) *PolicyManifest {
	return &PolicyManifest{Header: w.hdr(TypePolicy, ScopeAccount, acct, epoch, RoleCustodian),
		AccountID: acct, AccountKind: KindManaged, PoolID: wPool, TargetDescriptorDigest: w.targetD, CheckoutMode: mode,
		EnrollerPrincipalIDs: []UUID{w.users["alice"].id}, AutoStandingRelease: boolp(mode == ModeStanding),
		StandingRecipientPrincipalIDs: []UUID{}, AllowedUserPrincipalIDs: []UUID{w.users["alice"].id, w.users["bob"].id, w.users["dave"].id},
		AllowedApproverPrincipalIDs: []UUID{w.users["bob"].id}, RequiredApproverCount: 1, MaxCheckoutTTLSeconds: 3600,
		RotationSchedule: &Schedule{NewTime(wT0.Add(-24 * time.Hour)), 86400}, RecoveryEscrowEnabled: true}
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, users: map[string]*wPrincipal{}, pol: map[UUID]*PolicyManifest{}, polRaw: map[UUID][]byte{}}
	for i, l := range []string{"custodian-a", "custodian-b", "custodian-c"} {
		w.cust = append(w.cust, mustSigningKey(t, l))
		w.custIDs = append(w.custIDs, uuidN("0190b2a4-5555-7555-8555-00000000", i+1))
	}
	w.recovery = mustXWing(t, "recovery")
	b := Bundle{DeploymentID: wDeployment}
	b.CustodianSet = *w.custodianSet(1, 2, w.cust, w.custIDs)
	w.signed(&b.CustodianSet, RoleCustodian, w.cust[0], w.cust[1])
	b.RecoveryKey = *w.recoveryManifest(1, true)
	w.signed(&b.RecoveryKey, RoleCustodian, w.cust[0], w.cust[1])
	w.bundle = w.raw(&b)
	fp, err := BundleFingerprint(w.bundle)
	if err != nil {
		t.Fatal(err)
	}
	w.fp = fp.Hex()

	for i, n := range []string{"alice", "bob", "carol", "dave", "mallory"} {
		w.users[n] = &wPrincipal{uuidN("0190b2a4-6666-7666-8666-00000000", i+1), mustSigningKey(t, n), mustXWing(t, n)}
	}
	w.old = &wBroker{"4c2f0e1a-9b8d-4c6e-a7f3-2d1b0c9e8f01", mustSigningKey(t, "broker-old"), mustXWing(t, "broker-old"), hexOf("cert-old")}
	w.brkA = &wBroker{"4c2f0e1a-9b8d-4c6e-a7f3-2d1b0c9e8f02", mustSigningKey(t, "broker-a"), mustXWing(t, "broker-a"), hexOf("cert-a")}

	for _, n := range []string{"alice", "bob", "carol", "dave", "mallory"} {
		p := w.users[n]
		w.context = append(w.context, w.signed(w.enrollment(p, 1), RoleCustodian, w.cust[0], w.cust[1]))
		// The self-signature is appended after the custodians'; all sign one digest.
		w.context[len(w.context)-1] = w.reSign(w.context[len(w.context)-1], &KeyEnrollmentManifest{}, RoleUser, p.sig)
	}
	w.context = append(w.context,
		w.signed(w.pool(1, []BrokerMember{w.member(w.old, StatusActive)}, nil), RoleCustodian, w.cust[0], w.cust[1]),
		w.signed(w.pool(2, []BrokerMember{w.member(w.old, StatusRevoked), w.member(w.brkA, StatusActive)},
			[]Decommission{{w.old.id, "host wiped and key destroyed, attested by custodian-a and custodian-b"}}), RoleCustodian, w.cust[1], w.cust[2]))

	td := TargetDescriptor{DescriptorVersion: "1", DeploymentID: wDeployment, AccountID: wAcctE, AssetID: wAsset,
		ConnectorType: ConnectorSSHPasswd, AuthenticatedTargetIdentity: "svc-backup",
		Endpoint:        Endpoint{Host: "db1.internal.example.test", Port: 22, SSHHostKeySHA256: string(hexOf("ssh-host-key"))},
		ConnectorConfig: map[string]json.RawMessage{}, Dependencies: []json.RawMessage{}}
	w.target = w.raw(&td)
	_, d, err := DecodeTargetDescriptor(w.target)
	if err != nil {
		t.Fatal(err)
	}
	w.targetD = d.Hex()

	pe := w.managedPolicy(wAcctE, 1, ModeEphemeral)
	ps := w.managedPolicy(wAcctS, 1, ModeStanding)
	ps.StandingRecipientPrincipalIDs = []UUID{w.users["carol"].id}
	ps.RequiredApproverCount, ps.RecoveryEscrowEnabled = 0, false
	pv := &PolicyManifest{Header: w.hdr(TypePolicy, ScopeAccount, wAcctV, 1, RoleCustodian), AccountID: wAcctV, AccountKind: KindVaulted,
		AllowedUserPrincipalIDs: []UUID{w.users["alice"].id, w.users["dave"].id}, AllowedApproverPrincipalIDs: []UUID{},
		MaxCheckoutTTLSeconds: 0, RecoveryEscrowEnabled: true}
	for _, p := range []*PolicyManifest{pe, ps, pv} {
		r := w.signed(p, RoleCustodian, w.cust[0], w.cust[2])
		w.pol[p.AccountID], w.polRaw[p.AccountID] = p, r
		w.context = append(w.context, r)
	}
	w.trust = w.newTrust()
	return w
}

// reSign decodes raw into o, appends a signature and returns the new canonical JSON.
func (w *world) reSign(raw []byte, o Signed, role string, k *SigningKey) []byte {
	w.t.Helper()
	if _, err := canonical.Decode(raw, o); err != nil {
		w.t.Fatal(err)
	}
	return w.signed(o, role, k)
}

// newTrust builds the verified context state, as the consumer does from context.json.
func (w *world) newTrust() *Trust {
	w.t.Helper()
	tr, err := NewTrust(w.bundle, w.fp)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, m := range w.context {
		if _, err := tr.Accept(m); err != nil {
			w.t.Fatalf("context manifest: %v", err)
		}
	}
	return tr
}

func (w *world) policyDigest(acct UUID) HexID {
	d, err := ObjDigest(w.pol[acct])
	if err != nil {
		w.t.Fatal(err)
	}
	return d.Hex()
}
