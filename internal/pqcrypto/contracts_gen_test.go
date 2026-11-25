package pqcrypto

// Contract vectors (§3.8) for the object types of §3.2–§3.5. Every file is consumed against
// the state built from context.json: the bundle, its pinned fingerprint and the manifests
// accepted in order.

import (
	"encoding/json"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

func init() {
	generators["context.json"] = genContext
	generators["bootstrap.json"] = genBootstrap
	generators["custodian_set.json"] = genCustodianSet
	generators["recovery_key.json"] = genRecoveryKey
	generators["pool.json"] = genPool
	generators["policy.json"] = genPolicy
	generators["key_enrollment.json"] = genKeyEnrollment
	generators["target.json"] = genTarget
}

type contextFile struct {
	Bundle      json.RawMessage   `json:"bundle"`
	Fingerprint HexID             `json:"fingerprint"`
	Manifests   []json.RawMessage `json:"manifests"`
}

func genContext(t *testing.T) any {
	w := newWorld(t)
	c := contextFile{Bundle: w.bundle, Fingerprint: w.fp}
	for _, m := range w.context {
		c.Manifests = append(c.Manifests, m)
	}
	return c
}

// objParams are the inputs an operation takes besides the object and the context.
type objParams struct {
	Prior            []json.RawMessage `json:"prior,omitempty"`
	Pinned           HexID             `json:"pinned,omitempty"`
	Now              string            `json:"now,omitempty"`
	BrokerID         UUID              `json:"broker_id,omitempty"`
	Seen             []UUID            `json:"seen,omitempty"`
	Current          *currentParams    `json:"current,omitempty"`
	CandidateDigest  HexID             `json:"candidate_digest,omitempty"`
	CandidateVersion string            `json:"candidate_version,omitempty"`
	HighestVersion   string            `json:"highest_version,omitempty"`
	Tx               json.RawMessage   `json:"tx,omitempty"`
	Challenge        B64               `json:"challenge,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	New              bool              `json:"new,omitempty"`
	EnrollTx         json.RawMessage   `json:"enroll_tx,omitempty"`
	StandingRelease  json.RawMessage   `json:"standing_release,omitempty"`
	Envelope         json.RawMessage   `json:"envelope,omitempty"`
	Receipts         []json.RawMessage `json:"receipts,omitempty"`
	Remote           []json.RawMessage `json:"remote,omitempty"`
}

type currentParams struct {
	EnvelopeID    UUID   `json:"envelope_id"`
	SecretVersion string `json:"secret_version"`
	ReceiptHead   HexID  `json:"receipt_head"`
}

// objVector is one contract vector. Op names the operation: bundle, accept, target, tx,
// pop, envelope, receipt or extends. Canonical and Digest are given for accepted objects.
type objVector struct {
	Name      string          `json:"name"`
	Op        string          `json:"op"`
	Object    json.RawMessage `json:"object,omitempty"`
	Canonical string          `json:"canonical,omitempty"`
	Digest    HexID           `json:"digest,omitempty"`
	Params    objParams       `json:"params"`
	Verdict   string          `json:"verdict"`
}

// vec builds a vector; for an accepted object it records canonical bytes and D under typ.
func vec(t *testing.T, name, op, typ string, obj []byte, p objParams, verdict string) objVector {
	v := objVector{Name: name, Op: op, Object: obj, Params: p, Verdict: verdict}
	if verdict == ok && typ != "" {
		c, err := canonical.Canonicalize(obj)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DigestCanonical(typ, c)
		if err != nil {
			t.Fatal(err)
		}
		v.Canonical, v.Digest = string(c), d.Hex()
	}
	return v
}

// signOver appends a signature over an explicit digest, for wrong-domain and
// covered-field vectors.
func signOver(t *testing.T, sigs *[]Signature, role string, k *SigningKey, d Digest) {
	sig, err := k.Sign(d)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := k.Public().SigKeyID()
	*sigs = append(*sigs, Signature{role, id, sig})
}

func genBootstrap(t *testing.T) any {
	w := newWorld(t)
	bundle := func(cs *CustodianSetManifest, csKeys []*SigningKey, rk *RecoveryKeyManifest, rkKeys []*SigningKey) []byte {
		b := Bundle{DeploymentID: wDeployment, CustodianSet: *cs, RecoveryKey: *rk}
		w.signed(&b.CustodianSet, RoleCustodian, csKeys...)
		w.signed(&b.RecoveryKey, RoleCustodian, rkKeys...)
		return w.raw(&b)
	}
	fp := func(b []byte) HexID {
		d, err := BundleFingerprint(b)
		if err != nil {
			t.Fatal(err)
		}
		return d.Hex()
	}
	two := w.cust[:2]
	oneOfOne := bundle(w.custodianSet(1, 1, w.cust[:1], w.custIDs[:1]), w.cust[:1], w.recoveryManifest(1, false), w.cust[:1])
	short := bundle(w.custodianSet(1, 2, w.cust, w.custIDs), w.cust[:1], w.recoveryManifest(1, true), two)
	badRK := w.recoveryManifest(1, true)
	badRK.RecoveryKeyID = hexOf("not the recovery key")
	badID := bundle(w.custodianSet(1, 2, w.cust, w.custIDs), two, badRK, two)
	outsider := mustSigningKey(t, "outsider")
	byOutsider := bundle(w.custodianSet(1, 2, w.cust, w.custIDs), two, w.recoveryManifest(1, true), []*SigningKey{w.cust[0], outsider})
	ep2 := w.custodianSet(2, 2, w.cust, w.custIDs)
	notEpoch1 := bundle(ep2, two, w.recoveryManifest(1, true), two)
	lowRK := w.recoveryManifest(1, true)
	lowRK.Threshold = 1
	low := bundle(w.custodianSet(1, 2, w.cust, w.custIDs), two, lowRK, two)
	return []objVector{
		vec(t, "recovery threshold below 2", "bundle", "", low, objParams{Pinned: fp(low)}, "invalid_body"),
		vec(t, "bundle 2-of-3", "bundle", TypeBootstrap, w.bundle, objParams{Pinned: w.fp}, ok),
		vec(t, "1-of-1 custodian set accepted", "bundle", TypeBootstrap, oneOfOne, objParams{Pinned: fp(oneOfOne)}, ok),
		vec(t, "no trust pin", "bundle", "", w.bundle, objParams{}, "not_trusted"),
		vec(t, "different pinned fingerprint", "bundle", "", w.bundle, objParams{Pinned: fp(oneOfOne)}, "fingerprint_mismatch"),
		vec(t, "custodian set with M-1 signatures", "bundle", "", short, objParams{Pinned: fp(short)}, "threshold_not_met"),
		vec(t, "recovery_key_id not the key's enc_key_id", "bundle", "", badID, objParams{Pinned: fp(badID)}, "invalid_body"),
		vec(t, "recovery manifest signed outside the custodian set", "bundle", "", byOutsider, objParams{Pinned: fp(byOutsider)}, "unknown_signing_key"),
		vec(t, "custodian set not at epoch 1", "bundle", "", notEpoch1, objParams{Pinned: fp(notEpoch1)}, "invalid_body"),
	}
}

func genCustodianSet(t *testing.T) any {
	w := newWorld(t)
	newKey := mustSigningKey(t, "custodian-d")
	keys2 := []*SigningKey{w.cust[0], w.cust[1], newKey}
	ids2 := []UUID{w.custIDs[0], w.custIDs[1], uuidN("0190b2a4-5555-7555-8555-00000000", 4)}
	ep2 := w.signed(w.custodianSet(2, 2, keys2, ids2), RoleCustodian, w.cust[0], w.cust[2])
	ep2b := w.signed(w.custodianSet(2, 3, keys2, ids2), RoleCustodian, w.cust[0], w.cust[1])
	ep3skip := w.signed(w.custodianSet(3, 2, keys2, ids2), RoleCustodian, w.cust[0], w.cust[1])
	byNew := w.signed(w.custodianSet(2, 2, keys2, ids2), RoleCustodian, w.cust[0], newKey)
	ep3 := w.signed(w.custodianSet(3, 2, w.cust[:2], w.custIDs[:2]), RoleCustodian, w.cust[0], newKey) // signed by the epoch-2 set
	zero := w.signed(w.custodianSet(2, 0, keys2, ids2), RoleCustodian, w.cust[0], w.cust[1])
	return []objVector{
		vec(t, "epoch 2 signed by M of the previous set", "accept", TypeCustodianSet, ep2, objParams{}, ok),
		vec(t, "epoch 3 signed by M of the epoch-2 set", "accept", TypeCustodianSet, ep3, objParams{Prior: []json.RawMessage{ep2}}, ok),
		vec(t, "epoch 2 signed by a custodian of the new set only", "accept", "", byNew, objParams{}, "unknown_signing_key"),
		vec(t, "epoch skipped", "accept", "", ep3skip, objParams{}, "invalid_body"),
		vec(t, "same-epoch equivocation", "accept", "", ep2b, objParams{Prior: []json.RawMessage{ep2}}, "epoch_equivocation"),
		vec(t, "same epoch and digest is idempotent", "accept", TypeCustodianSet, ep2, objParams{Prior: []json.RawMessage{ep2}}, ok),
		vec(t, "rollback to epoch 1 after epoch 2", "accept", "", w.raw(&w.trustBundle().CustodianSet), objParams{Prior: []json.RawMessage{ep2}}, "epoch_rollback"),
		vec(t, "threshold 0", "accept", "", zero, objParams{}, "invalid_body"),
	}
}

// trustBundle decodes the world's bundle.
func (w *world) trustBundle() *Bundle {
	var b Bundle
	if _, err := canonical.Decode(w.bundle, &b); err != nil {
		w.t.Fatal(err)
	}
	return &b
}

func genRecoveryKey(t *testing.T) any {
	w := newWorld(t)
	ep2 := w.signed(w.recoveryManifest(2, false), RoleCustodian, w.cust[0], w.cust[1])
	other := w.recoveryManifest(2, true)
	other.RecoveryPubkey = w.users["mallory"].enc.Public().Bytes()
	other.RecoveryKeyID = w.users["mallory"].encID()
	swapped := w.signed(other, RoleCustodian, w.cust[0], w.cust[1])
	topo := w.recoveryManifest(2, true)
	topo.Threshold, topo.TotalShares = 3, 5
	retopo := w.signed(topo, RoleCustodian, w.cust[0], w.cust[1])
	return []objVector{
		vec(t, "epoch 2 changes only the escrow default", "accept", TypeRecoveryKey, ep2, objParams{}, ok),
		vec(t, "epoch 2 replaces the recovery key (frozen until D.7)", "accept", "", swapped, objParams{}, "invalid_body"),
		vec(t, "epoch 2 changes the topology (frozen until D.7)", "accept", "", retopo, objParams{}, "invalid_body"),
		vec(t, "M-1 custodian signatures", "accept", "", w.signed(w.recoveryManifest(2, false), RoleCustodian, w.cust[2]), objParams{}, "threshold_not_met"),
	}
}

func genPool(t *testing.T) any {
	w := newWorld(t)
	b3 := &wBroker{"4c2f0e1a-9b8d-4c6e-a7f3-2d1b0c9e8f03", mustSigningKey(t, "broker-b"), mustXWing(t, "broker-b"), hexOf("cert-b")}
	decom := []Decommission{{w.old.id, "host wiped and key destroyed, attested by custodian-a and custodian-b"}}
	p := func(members []BrokerMember, d []Decommission) []byte {
		return w.signed(w.pool(3, members, d), RoleCustodian, w.cust[0], w.cust[1])
	}
	old, a, b := w.member(w.old, StatusRevoked), w.member(w.brkA, StatusActive), w.member(b3, StatusActive)
	aRev := w.member(w.brkA, StatusRevoked)
	reactivated := w.member(w.old, StatusActive)
	bad := w.pool(3, []BrokerMember{old, a}, decom)
	bad.Signatures = nil
	signOver(t, &bad.Signatures, RoleCustodian, w.cust[0], w.digestAs(TypePolicy, bad))
	signOver(t, &bad.Signatures, RoleCustodian, w.cust[1], w.digestAs(TypePolicy, bad))
	onlyML := w.pool(3, []BrokerMember{old, aRev, b}, decom)
	w.signed(onlyML, RoleCustodian, w.cust[0], w.cust[1])
	onlyML.Signatures[1].Sig.Ed25519 = nil
	onlyEd := w.pool(3, []BrokerMember{old, aRev, b}, decom)
	w.signed(onlyEd, RoleCustodian, w.cust[0], w.cust[1])
	onlyEd.Signatures[0].Sig.MLDSA65 = nil
	roleLie := w.pool(3, []BrokerMember{old, aRev, b}, decom)
	w.signed(roleLie, RoleCustodian, w.cust[0])
	w.signed(roleLie, RoleUser, w.cust[1])
	return []objVector{
		vec(t, "replace the active broker", "accept", TypePool, p([]BrokerMember{old, aRev, b}, decom), objParams{}, ok),
		vec(t, "revoked member (not decommissioned) re-activated", "accept", "", w.signed(w.pool(4, []BrokerMember{old, a, w.member(b3, StatusRevoked)}, decom), RoleCustodian, w.cust[0], w.cust[1]), objParams{Prior: []json.RawMessage{p([]BrokerMember{old, aRev, b}, decom)}}, "invalid_body"),
		vec(t, "two active brokers in 1A", "accept", "", p([]BrokerMember{old, a, b}, decom), objParams{}, "unsupported_in_phase"),
		vec(t, "revoked member dropped", "accept", "", p([]BrokerMember{a}, []Decommission{}), objParams{}, "invalid_body"),
		vec(t, "revoked member re-activated", "accept", "", p([]BrokerMember{reactivated, aRev}, []Decommission{}), objParams{}, "invalid_body"),
		vec(t, "decommission of a non-member", "accept", "", p([]BrokerMember{old, a}, []Decommission{{b3.id, "x"}}), objParams{}, "invalid_body"),
		vec(t, "decommission of an active member", "accept", "", p([]BrokerMember{old, a}, []Decommission{decom[0], {w.brkA.id, "x"}}), objParams{}, "invalid_body"),
		vec(t, "decommission record dropped", "accept", "", p([]BrokerMember{old, a}, []Decommission{}), objParams{}, "invalid_body"),
		vec(t, "signed under the wrong domain type", "accept", "", w.raw(bad), objParams{}, "invalid_signature"),
		vec(t, "one custodian signature has only the ML-DSA half", "accept", "", w.raw(onlyML), objParams{}, "invalid_signature"),
		vec(t, "one custodian signature has only the Ed25519 half", "accept", "", w.raw(onlyEd), objParams{}, "invalid_signature"),
		vec(t, "custodian key signing as signer_role user", "accept", "", w.raw(roleLie), objParams{}, "signer_role_mismatch"),
		vec(t, "rollback to epoch 1", "accept", "", w.context[5], objParams{}, "epoch_rollback"),
	}
}

// digestAs computes D of o under another type, for the wrong-domain vector.
func (w *world) digestAs(typ string, o any) Digest {
	d, err := D(typ, o)
	if err != nil {
		w.t.Fatal(err)
	}
	return d
}

func genPolicy(t *testing.T) any {
	w := newWorld(t)
	c := w.cust
	ep2 := w.managedPolicy(wAcctE, 2, ModeEphemeral)
	ep2.RequiredApproverCount = 0
	ep2raw := w.signed(ep2, RoleCustodian, c[0], c[1])
	fork := w.managedPolicy(wAcctE, 1, ModeEphemeral)
	fork.AllowedUserPrincipalIDs = append(fork.AllowedUserPrincipalIDs, w.users["mallory"].id)
	proxy := w.managedPolicy(wAcctE, 2, ModeProxyOnly)
	zero := w.managedPolicy(wAcctE, 2, ModeEphemeral)
	zero.RotationSchedule.IntervalSeconds = 0
	kind := w.managedPolicy(wAcctV, 2, ModeEphemeral)
	vaultedMode := *w.pol[wAcctV]
	vaultedMode.Signatures, vaultedMode.Epoch, vaultedMode.CheckoutMode = nil, 2, ModeEphemeral
	outsider := mustSigningKey(t, "outsider")
	return []objVector{
		vec(t, "policy epoch 2", "accept", TypePolicy, ep2raw, objParams{}, ok),
		vec(t, "same epoch and digest is idempotent", "accept", TypePolicy, w.polRaw[wAcctE], objParams{}, ok),
		vec(t, "same-epoch equivocation", "accept", "", w.signed(fork, RoleCustodian, c[0], c[1]), objParams{}, "epoch_equivocation"),
		vec(t, "rollback to epoch 1 after epoch 2", "accept", "", w.polRaw[wAcctE], objParams{Prior: []json.RawMessage{ep2raw}}, "epoch_rollback"),
		vec(t, "proxy_only rejected in 1A", "accept", "", w.signed(proxy, RoleCustodian, c[0], c[1]), objParams{}, "unsupported_in_phase"),
		vec(t, "interval_seconds of 0", "accept", "", w.signed(zero, RoleCustodian, c[0], c[1]), objParams{}, "invalid_body"),
		vec(t, "M-1 custodian signatures", "accept", "", w.signed(w.managedPolicy(wAcctE, 2, ModeEphemeral), RoleCustodian, c[0]), objParams{}, "threshold_not_met"),
		vec(t, "signed by a key outside the custodian set", "accept", "", w.signed(w.managedPolicy(wAcctE, 2, ModeEphemeral), RoleCustodian, c[0], outsider), objParams{}, "unknown_signing_key"),
		vec(t, "account kind changed", "accept", "", w.signed(kind, RoleCustodian, c[0], c[1]), objParams{}, "invalid_body"),
		vec(t, "managed-only field on a vaulted policy", "accept", "", w.signed(&vaultedMode, RoleCustodian, c[0], c[1]), objParams{}, "invalid_body"),
	}
}

func genKeyEnrollment(t *testing.T) any {
	w := newWorld(t)
	c := w.cust
	alice := w.users["alice"]
	fresh := &wPrincipal{alice.id, mustSigningKey(t, "alice-2"), mustXWing(t, "alice-2")}
	add := func(epoch Counter, keys ...EnrolledKey) *KeyEnrollmentManifest {
		m := w.enrollment(alice, epoch)
		m.Keys = append(m.Keys, keys...)
		return m
	}
	sid2, _ := fresh.sig.Public().SigKeyID()
	k2 := EnrolledKey{fresh.enc.Public().Bytes(), fresh.encID(), fresh.sig.Public(), sid2, StatusActive}
	both := add(2, k2)
	good := w.signed(both, RoleCustodian, c[0], c[1])
	good = w.reSign(good, &KeyEnrollmentManifest{}, RoleUser, alice.sig)
	good = w.reSign(good, &KeyEnrollmentManifest{}, RoleUser, fresh.sig)
	missing := w.reSign(w.signed(add(2, k2), RoleCustodian, c[0], c[1]), &KeyEnrollmentManifest{}, RoleUser, alice.sig)
	noCust := w.signed(add(2, k2), RoleUser, alice.sig, fresh.sig)
	revoked := w.enrollment(alice, 2)
	revoked.Keys[0].Status = StatusRevoked
	revoked.Keys = append(revoked.Keys, k2)
	rev := w.reSign(w.signed(revoked, RoleCustodian, c[0], c[1]), &KeyEnrollmentManifest{}, RoleUser, fresh.sig)
	dropped := w.enrollment(fresh, 2)
	drop := w.reSign(w.signed(dropped, RoleCustodian, c[0], c[1]), &KeyEnrollmentManifest{}, RoleUser, fresh.sig)
	userAsCust := w.signed(add(2, k2), RoleCustodian, c[0], c[1], alice.sig)
	stolen := w.enrollment(w.users["mallory"], 2)
	stolen.Keys = append(stolen.Keys, w.enrollment(alice, 1).Keys[0])
	steal := w.signed(stolen, RoleCustodian, c[0], c[1])
	steal = w.reSign(steal, &KeyEnrollmentManifest{}, RoleUser, w.users["mallory"].sig)
	steal = w.reSign(steal, &KeyEnrollmentManifest{}, RoleUser, alice.sig)
	renamed := w.enrollment(alice, 2)
	renamed.Issuer = "https://other-idp.example.test"
	rename := w.reSign(w.signed(renamed, RoleCustodian, c[0], c[1]), &KeyEnrollmentManifest{}, RoleUser, alice.sig)
	back := w.enrollment(alice, 3)
	back.Keys = append(back.Keys, k2)
	reactivate := w.signed(back, RoleCustodian, c[0], c[1])
	reactivate = w.reSign(reactivate, &KeyEnrollmentManifest{}, RoleUser, alice.sig)
	reactivate = w.reSign(reactivate, &KeyEnrollmentManifest{}, RoleUser, fresh.sig)
	return []objVector{
		vec(t, "issuer changed", "accept", "", rename, objParams{}, "invalid_body"),
		vec(t, "revoked key re-activated", "accept", "", reactivate, objParams{Prior: []json.RawMessage{rev}}, "invalid_body"),
		vec(t, "second key: custodian and self-signatures over one digest", "accept", TypeKeyEnrollment, good, objParams{}, ok),
		vec(t, "revoke the first key, keep it listed", "accept", TypeKeyEnrollment, rev, objParams{}, ok),
		vec(t, "active key without its self-signature", "accept", "", missing, objParams{}, "missing_self_signature"),
		vec(t, "self-signatures only", "accept", "", noCust, objParams{}, "threshold_not_met"),
		vec(t, "listed key dropped", "accept", "", drop, objParams{}, "invalid_body"),
		vec(t, "user key signing as signer_role custodian", "accept", "", userAsCust, objParams{}, "signer_role_mismatch"),
		vec(t, "key already enrolled to another principal", "accept", "", steal, objParams{}, "invalid_body"),
	}
}

func genTarget(t *testing.T) any {
	w := newWorld(t)
	base := func() TargetDescriptor {
		var td TargetDescriptor
		if _, err := canonical.Decode(w.target, &td); err != nil {
			t.Fatal(err)
		}
		return td
	}
	ad := base()
	ad.ConnectorType, ad.AuthenticatedTargetIdentity = ConnectorADLDAPS, "CN=svc-backup,OU=Service,DC=corp,DC=example,DC=test"
	ad.Endpoint = Endpoint{Host: "dc1.corp.example.test", Port: 636, TLSCAPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"}
	cfg := base()
	cfg.ConnectorConfig = map[string]json.RawMessage{"script": json.RawMessage(`"x"`)}
	dep := base()
	dep.Dependencies = []json.RawMessage{json.RawMessage(`{"kind":"service"}`)}
	other := base()
	other.ConnectorType = "sql_server"
	nokey := base()
	nokey.Endpoint.SSHHostKeySHA256 = ""
	adNoCA := ad
	adNoCA.Endpoint.TLSCAPEM = ""
	return []objVector{
		vec(t, "ssh_passwd descriptor", "target", TypeTarget, w.target, objParams{}, ok),
		vec(t, "ad_ldaps descriptor", "target", TypeTarget, w.raw(&ad), objParams{}, ok),
		vec(t, "non-empty connector_config", "target", "", w.raw(&cfg), objParams{}, "unsupported_in_phase"),
		vec(t, "non-empty dependencies", "target", "", w.raw(&dep), objParams{}, "unsupported_in_phase"),
		vec(t, "connector outside the 1A slice", "target", "", w.raw(&other), objParams{}, "unsupported_in_phase"),
		vec(t, "ssh_passwd without host key", "target", "", w.raw(&nokey), objParams{}, "invalid_body"),
		vec(t, "ad_ldaps without CA", "target", "", w.raw(&adNoCA), objParams{}, "invalid_body"),
	}
}
