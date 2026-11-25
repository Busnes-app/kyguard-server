package pqcrypto

import (
	"encoding/json"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// ErrSelfSignature reports a key enrollment missing a self-signature by an active key.
const ErrSelfSignature Error = "missing_self_signature"

// Bundle is the DeploymentBootstrapBundle, the trust root (§3.2). It is not signed itself;
// its fingerprint is D(bundle) with type "bootstrap", checked out of band.
type Bundle struct {
	DeploymentID UUID                 `json:"deployment_id"`
	CustodianSet CustodianSetManifest `json:"custodian_set"`
	RecoveryKey  RecoveryKeyManifest  `json:"recovery_key"`
}

// BundleFingerprint returns D(bundle) of raw bundle JSON without verifying its contents.
func BundleFingerprint(raw []byte) (Digest, error) {
	var b Bundle
	canon, err := canonical.Decode(raw, &b)
	if err != nil {
		return Digest{}, err
	}
	return DigestCanonical(TypeBootstrap, canon)
}

// Record is one verified manifest and its high-water mark.
type Record struct {
	Type      string
	ScopeID   UUID
	Epoch     Counter
	Digest    Digest
	Canonical []byte
	Manifest  Signed
}

type recordKey struct {
	typ   string
	scope UUID
}

// Trust is the verified manifest state a broker or CLI keeps (§3.7): the pinned bundle,
// the current custodian set and recovery manifest, and the latest verified manifest per
// (type, scope.id). Persistence is the caller's; Accept is the only way in.
type Trust struct {
	deployment  UUID
	fingerprint Digest
	records     map[recordKey]*Record
	policies    map[Digest]*PolicyManifest // every policy accepted, for sealing contexts
	order       []*Record                  // acceptance order, for persistence
}

// NewTrust verifies a bundle against the fingerprint pinned out of band. Without a match it
// returns ErrFingerprint and no state.
func NewTrust(rawBundle []byte, pinned HexID) (*Trust, error) {
	if !pinned.Valid() {
		return nil, ErrNotTrusted
	}
	var b Bundle
	canon, err := canonical.Decode(rawBundle, &b)
	if err != nil {
		return nil, err
	}
	fp, err := DigestCanonical(TypeBootstrap, canon)
	if err != nil {
		return nil, err
	}
	if fp.Hex() != pinned {
		return nil, ErrFingerprint
	}
	if !b.DeploymentID.Valid() {
		return nil, ErrBody
	}
	t := &Trust{deployment: b.DeploymentID, fingerprint: fp, records: map[recordKey]*Record{}, policies: map[Digest]*PolicyManifest{}}
	cs, err := canonical.Marshal(&b.CustodianSet)
	if err != nil {
		return nil, err
	}
	rk, err := canonical.Marshal(&b.RecoveryKey)
	if err != nil {
		return nil, err
	}
	if b.CustodianSet.Epoch != 1 || b.RecoveryKey.Epoch != 1 {
		return nil, ErrBody
	}
	for _, raw := range [][]byte{cs, rk} {
		if _, err := t.Accept(raw); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// DeploymentID is the pinned deployment.
func (t *Trust) DeploymentID() UUID { return t.deployment }

// Fingerprint is the pinned bootstrap fingerprint.
func (t *Trust) Fingerprint() HexID { return t.fingerprint.Hex() }

// Records returns every accepted manifest in acceptance order. Re-accepting them in this
// order into NewTrust rebuilds the same state.
func (t *Trust) Records() []*Record { return append([]*Record(nil), t.order...) }

// Lookup returns the current record for (type, scope.id), or nil.
func (t *Trust) Lookup(typ string, scope UUID) *Record { return t.records[recordKey{typ, scope}] }

// CustodianSet returns the current custodian set.
func (t *Trust) CustodianSet() *CustodianSetManifest {
	return t.Lookup(TypeCustodianSet, t.deployment).Manifest.(*CustodianSetManifest)
}

// RecoveryKey returns the current recovery manifest.
func (t *Trust) RecoveryKey() *RecoveryKeyManifest {
	return t.Lookup(TypeRecoveryKey, t.deployment).Manifest.(*RecoveryKeyManifest)
}

// Policy returns the current policy for an account and its digest, or nil.
func (t *Trust) Policy(account UUID) (*PolicyManifest, Digest) {
	r := t.Lookup(TypePolicy, account)
	if r == nil {
		return nil, Digest{}
	}
	return r.Manifest.(*PolicyManifest), r.Digest
}

// PolicyByDigest returns any accepted policy by its digest: an envelope's sealing context.
func (t *Trust) PolicyByDigest(d HexID) *PolicyManifest {
	for k, p := range t.policies {
		if k.Hex() == d {
			return p
		}
	}
	return nil
}

// policyAt returns the accepted policy of an account at an epoch, or nil.
func (t *Trust) policyAt(account UUID, epoch Counter) *PolicyManifest {
	for _, p := range t.policies {
		if p.AccountID == account && p.Epoch == epoch {
			return p
		}
	}
	return nil
}

// Pool returns the current pool manifest, or nil.
func (t *Trust) Pool(pool UUID) *BrokerPoolManifest {
	if r := t.Lookup(TypePool, pool); r != nil {
		return r.Manifest.(*BrokerPoolManifest)
	}
	return nil
}

// Enrollment returns the current key enrollment for a principal, or nil.
func (t *Trust) Enrollment(principal UUID) *KeyEnrollmentManifest {
	if r := t.Lookup(TypeKeyEnrollment, principal); r != nil {
		return r.Manifest.(*KeyEnrollmentManifest)
	}
	return nil
}

type manifest interface {
	Signed
	validate() error
}

// newManifest returns an empty manifest of a type this binary builds.
func newManifest(typ string) (manifest, error) {
	switch typ {
	case TypeCustodianSet:
		return &CustodianSetManifest{}, nil
	case TypeRecoveryKey:
		return &RecoveryKeyManifest{}, nil
	case TypePool:
		return &BrokerPoolManifest{}, nil
	case TypePolicy:
		return &PolicyManifest{}, nil
	case TypeKeyEnrollment:
		return &KeyEnrollmentManifest{}, nil
	}
	return nil, ErrType
}

// PeekType returns the top-level "type" of a JSON object.
func PeekType(raw []byte) (string, error) {
	var h struct {
		Type string `json:"type"`
	}
	if _, err := canonical.Parse(raw); err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return "", ErrType
	}
	return h.Type, nil
}

// Accept verifies a manifest (§3.7 rule 1) and, if it is new, makes it current. A lower
// epoch is ErrRollback; the same epoch with another digest is ErrEquivocation, which the
// caller must alert on; the same epoch and digest is an idempotent success.
func (t *Trust) Accept(raw []byte) (*Record, error) {
	typ, err := PeekType(raw)
	if err != nil {
		return nil, err
	}
	m, err := newManifest(typ)
	if err != nil {
		return nil, err
	}
	canon, d, err := decodeSigned(raw, m)
	if err != nil {
		return nil, err
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	h := m.head()
	if h.DeploymentID != t.deployment {
		return nil, ErrDeployment
	}
	key := recordKey{typ, h.Scope.ID}
	prev := t.records[key]
	if prev != nil {
		switch {
		case h.Epoch < prev.Epoch:
			return nil, ErrRollback
		case h.Epoch == prev.Epoch && d != prev.Digest:
			return nil, ErrEquivocation
		case h.Epoch == prev.Epoch:
			return prev, nil // D excludes signatures: the same object, perhaps re-signed
		}
	}
	if err := t.checkSignatures(m, d, prev == nil); err != nil {
		return nil, err
	}
	if err := t.checkSuccessor(m, prev); err != nil {
		return nil, err
	}
	if ke, ok := m.(*KeyEnrollmentManifest); ok {
		if err := t.checkKeysUnique(ke); err != nil {
			return nil, err
		}
	}
	rec := &Record{typ, h.Scope.ID, h.Epoch, d, canon, m}
	t.records[key] = rec
	t.order = append(t.order, rec)
	if p, ok := m.(*PolicyManifest); ok {
		t.policies[d] = p
	}
	return rec, nil
}

// checkSignatures requires M custodians of the persisted set (epoch 1 custodian set: M of
// itself) and, for key enrollments, a self-signature by every active key.
func (t *Trust) checkSignatures(m manifest, d Digest, first bool) error {
	var set *CustodianSetManifest
	if cs, ok := m.(*CustodianSetManifest); ok && first {
		set = cs // epoch 1, from the bundle
	} else if r := t.Lookup(TypeCustodianSet, t.deployment); r != nil {
		set = r.Manifest.(*CustodianSetManifest)
	} else {
		return ErrNotTrusted
	}
	ring, err := set.ring()
	if err != nil {
		return err
	}
	ke, isKE := m.(*KeyEnrollmentManifest)
	if isKE {
		own, err := ke.ring(true)
		if err != nil {
			return err
		}
		for id, k := range own {
			if _, clash := ring[id]; clash {
				return ErrBody
			}
			ring[id] = k
		}
	}
	owners, err := verifySigs(d, *m.sigs(), ring)
	if err != nil {
		return err
	}
	if len(owners[RoleCustodian]) < set.Threshold {
		return ErrThreshold
	}
	if isKE {
		signed := map[HexID]bool{}
		for _, s := range ke.Signatures {
			signed[s.SigKeyID] = true
		}
		for _, k := range ke.Keys {
			if k.Status == StatusActive && !signed[k.SigKeyID] {
				return ErrSelfSignature
			}
		}
	}
	return nil
}

// checkSuccessor applies the per-type rules between consecutive epochs.
func (t *Trust) checkSuccessor(m manifest, prev *Record) error {
	if prev == nil {
		if cs, ok := m.(*CustodianSetManifest); ok && cs.Epoch != 1 {
			return ErrBody
		}
		return nil
	}
	switch n := m.(type) {
	case *CustodianSetManifest:
		// Every custodian-set epoch is kept, so the chain from the bundle is complete.
		if n.Epoch != prev.Epoch+1 {
			return ErrBody
		}
	case *RecoveryKeyManifest:
		// The recovery key and topology are frozen until migration ships (§9.4, D.7).
		p := prev.Manifest.(*RecoveryKeyManifest)
		if n.RecoveryKeyID != p.RecoveryKeyID || n.Threshold != p.Threshold || n.TotalShares != p.TotalShares {
			return ErrBody
		}
	case *BrokerPoolManifest:
		return n.checkSuccessor(prev.Manifest.(*BrokerPoolManifest))
	case *PolicyManifest:
		if n.AccountKind != prev.Manifest.(*PolicyManifest).AccountKind {
			return ErrBody
		}
	case *KeyEnrollmentManifest:
		return n.checkSuccessor(prev.Manifest.(*KeyEnrollmentManifest))
	}
	return nil
}

// checkSuccessor keeps identity fixed and every listed key listed, and never re-activates a
// revoked key, so historical user signatures keep verifying.
func (m *KeyEnrollmentManifest) checkSuccessor(prev *KeyEnrollmentManifest) error {
	if m.Issuer != prev.Issuer || m.Subject != prev.Subject {
		return ErrBody
	}
	for _, p := range prev.Keys {
		found := false
		for _, k := range m.Keys {
			if k.SigKeyID == p.SigKeyID && k.EncKeyID == p.EncKeyID {
				found = !(p.Status == StatusRevoked && k.Status != StatusRevoked)
			}
		}
		if !found {
			return ErrBody
		}
	}
	return nil
}

// checkKeysUnique keeps every user key bound to one principal, so a signature resolves to
// exactly one identity.
func (t *Trust) checkKeysUnique(ke *KeyEnrollmentManifest) error {
	for _, r := range t.records {
		other, ok := r.Manifest.(*KeyEnrollmentManifest)
		if !ok || other.PrincipalID == ke.PrincipalID {
			continue
		}
		for _, a := range ke.Keys {
			for _, b := range other.Keys {
				if a.SigKeyID == b.SigKeyID || a.EncKeyID == b.EncKeyID {
					return ErrBody
				}
			}
		}
	}
	return nil
}
