package pqcrypto

import (
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Object types: the <type> of each domain string (§3.2).
const (
	TypeBootstrap     = "bootstrap"
	TypeCustodianSet  = "custodian_set"
	TypeRecoveryKey   = "recovery_key"
	TypePool          = "pool"
	TypePolicy        = "policy"
	TypeKeyEnrollment = "key_enrollment"
	TypeTx            = "tx"
	TypeEnvelope      = "envelope"
	TypeReceipt       = "receipt"
	TypePoP           = "pop"
	TypeTarget        = "target"
)

// Signer roles.
const (
	RoleCustodian = "custodian"
	RoleBroker    = "broker"
	RoleUser      = "user"
	RoleCnf       = "cnf"
)

// Scope kinds.
const (
	ScopeDeployment = "deployment"
	ScopePool       = "pool"
	ScopeAccount    = "account"
	ScopePrincipal  = "principal"
)

// Errors returned by the signed-object layer.
const (
	ErrHeader       Error = "invalid_header"
	ErrDeployment   Error = "wrong_deployment"
	ErrBody         Error = "invalid_body"
	ErrSignerRole   Error = "signer_role_mismatch"
	ErrUnknownKey   Error = "unknown_signing_key"
	ErrThreshold    Error = "threshold_not_met"
	ErrRollback     Error = "epoch_rollback"
	ErrEquivocation Error = "epoch_equivocation"
	ErrFingerprint  Error = "fingerprint_mismatch"
	ErrNotTrusted   Error = "not_trusted"
	ErrUnsupported  Error = "unsupported_in_phase"
)

// Scope names what a signed object governs.
type Scope struct {
	Kind string `json:"kind"`
	ID   UUID   `json:"id"`
}

// Header is carried inside the signed bytes of every signed object (§3.2).
type Header struct {
	Type         string  `json:"type"`
	DeploymentID UUID    `json:"deployment_id"`
	Epoch        Counter `json:"epoch"`
	Scope        Scope   `json:"scope"`
	SignerRole   string  `json:"signer_role"`
}

// Signature is one entry of "signatures"; it is excluded from D(obj).
type Signature struct {
	SignerRole string    `json:"signer_role"`
	SigKeyID   HexID     `json:"sig_key_id"`
	Sig        HybridSig `json:"sig"`
}

// Signed is implemented by every signed object type.
type Signed interface {
	head() *Header
	sigs() *[]Signature
}

func (h *Header) head() *Header { return h }

// Sigs holds an object's signatures; embed it after the body.
type Sigs struct {
	Signatures []Signature `json:"signatures"`
}

func (s *Sigs) sigs() *[]Signature { return &s.Signatures }

// checkHeader enforces type, scope kind and signer role.
func checkHeader(h *Header, typ, scopeKind, role string) error {
	if h.Type != typ || h.Scope.Kind != scopeKind || h.SignerRole != role || !h.DeploymentID.Valid() || !h.Scope.ID.Valid() {
		return ErrHeader
	}
	return nil
}

// ObjDigest returns D(obj) for a signed object.
func ObjDigest(o Signed) (Digest, error) { return D(o.head().Type, o) }

// Sign appends a signature by k in role to o.
func Sign(o Signed, role string, k *SigningKey) error {
	d, err := ObjDigest(o)
	if err != nil {
		return err
	}
	sig, err := k.Sign(d)
	if err != nil {
		return err
	}
	id, err := k.Public().SigKeyID()
	if err != nil {
		return err
	}
	s := o.sigs()
	*s = append(*s, Signature{role, id, sig})
	return nil
}

// decodeSigned strictly decodes raw into o and returns its canonical bytes and D.
func decodeSigned(raw []byte, o Signed) ([]byte, Digest, error) {
	canon, err := canonical.Decode(raw, o)
	if err != nil {
		return nil, Digest{}, err
	}
	d, err := DigestCanonical(o.head().Type, canon)
	if err != nil {
		return nil, Digest{}, err
	}
	return canon, d, nil
}

// keyRing maps sig_key_id to the public key and the role it may sign as.
type keyRing map[HexID]ringKey

type ringKey struct {
	role  string
	owner string // custodian, broker or principal ID
	pub   HybridPub
}

func (r keyRing) add(role, owner string, pub HybridPub) error {
	id, err := pub.SigKeyID()
	if err != nil {
		return err
	}
	if _, dup := r[id]; dup {
		return ErrBody
	}
	r[id] = ringKey{role, owner, pub}
	return nil
}

// verifySigs checks every signature of o against ring and returns the distinct owners per
// role whose signatures verified. Any signature that fails, names an unknown key, or names a
// key of another role rejects the object: a signed object never carries a bad signature.
func verifySigs(d Digest, sigs []Signature, ring keyRing) (map[string]map[string]bool, error) {
	owners := map[string]map[string]bool{}
	seen := map[HexID]bool{}
	for _, s := range sigs {
		k, ok := ring[s.SigKeyID]
		if !ok {
			return nil, ErrUnknownKey
		}
		if k.role != s.SignerRole {
			return nil, ErrSignerRole
		}
		if seen[s.SigKeyID] {
			return nil, ErrBody
		}
		seen[s.SigKeyID] = true
		if err := k.pub.Verify(d, s.Sig); err != nil {
			return nil, err
		}
		if owners[k.role] == nil {
			owners[k.role] = map[string]bool{}
		}
		owners[k.role][k.owner] = true
	}
	return owners, nil
}
