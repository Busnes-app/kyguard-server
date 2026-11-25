package pqcrypto

import (
	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// Recipient types.
const (
	RecipientBroker   = "broker"
	RecipientUser     = "user"
	RecipientRecovery = "recovery"
)

// wrappedDEKBytes is a 32-byte DEK plus the AES-256-GCM tag.
const wrappedDEKBytes = DEKBytes + 16

// Recipient is one DEK wrap.
type Recipient struct {
	RecipientType string `json:"recipient_type"`
	RecipientID   string `json:"recipient_id"`
	KeyID         HexID  `json:"key_id"`
	Enc           B64    `json:"enc"`
	WrappedDEK    B64    `json:"wrapped_dek"`
}

func (r *Recipient) shape() error {
	if !validRecipient(r.RecipientType, r.RecipientID) || !r.KeyID.Valid() ||
		len(r.Enc) != recoverykey.EncapsulationBytes || len(r.WrappedDEK) != wrappedDEKBytes {
		return ErrRecipients
	}
	return nil
}

// SecretEnvelope is type envelope, account scope; its epoch is the policy epoch at sealing.
type SecretEnvelope struct {
	Header
	EnvelopeKind  string      `json:"envelope_kind"`
	EnvelopeID    UUID        `json:"envelope_id"`
	SecretVersion Counter     `json:"secret_version"`
	PolicyDigest  HexID       `json:"policy_digest"`
	RecoveryEpoch Counter     `json:"recovery_epoch"`
	CreatedAt     Time        `json:"created_at"`
	Nonce         B64         `json:"nonce"`
	Ciphertext    B64         `json:"ciphertext"`
	Recipients    []Recipient `json:"recipients"`
	Sigs
}

// PayloadAAD returns the payload AAD fields of the envelope.
func (e *SecretEnvelope) PayloadAAD() PayloadAADFields {
	return PayloadAADFields{e.EnvelopeKind, e.EnvelopeID, e.Scope.ID, e.SecretVersion, e.Epoch, e.PolicyDigest, e.RecoveryEpoch}
}

// RecipientAAD returns the DEK-wrap AAD fields for one recipient.
func (e *SecretEnvelope) RecipientAAD(r Recipient) RecipientAADFields {
	return RecipientAADFields{e.EnvelopeKind, e.EnvelopeID, e.Scope.ID, e.SecretVersion, r.RecipientID, r.RecipientType, r.KeyID}
}

// EnvelopeContext says how an envelope is being used.
type EnvelopeContext struct {
	// New is true when the envelope is being sealed, accepted as a candidate or unwrapped
	// now: its signer and broker recipient must then be active, and the recovery epoch the
	// persisted one. False verifies an envelope already in a chain (history).
	New bool
	// Enroll is the verified enroll transaction a user-signed managed envelope must match.
	Enroll *AccessTransaction
}

// VerifiedEnvelope is an envelope that passed VerifyEnvelope.
type VerifiedEnvelope struct {
	*SecretEnvelope
	Digest Digest
	Policy *PolicyManifest // the sealing context
	Signer UUID            // broker_id or principal_id
}

// RotationEnvelope reports whether a broker sealed it (a managed rotation envelope).
func (v *VerifiedEnvelope) RotationEnvelope() bool { return v.SignerRole == RoleBroker }

// VerifyEnvelope checks an envelope against its own sealing context and §3.5's signer,
// recipient and escrow rules, before anything is unwrapped or signed.
func (t *Trust) VerifyEnvelope(raw []byte, c EnvelopeContext) (*VerifiedEnvelope, error) {
	var e SecretEnvelope
	_, d, err := decodeSigned(raw, &e)
	if err != nil {
		return nil, err
	}
	if e.Type != TypeEnvelope || e.Scope.Kind != ScopeAccount || !e.Scope.ID.Valid() || !e.DeploymentID.Valid() ||
		(e.SignerRole != RoleBroker && e.SignerRole != RoleUser) {
		return nil, ErrHeader
	}
	if e.DeploymentID != t.deployment {
		return nil, ErrDeployment
	}
	if !validKind(e.EnvelopeKind) || !v7(e.EnvelopeID) || e.SecretVersion < 1 || len(e.Nonce) != NonceBytes ||
		len(e.Ciphertext) < 16 || !e.PolicyDigest.Valid() {
		return nil, ErrBody
	}
	pol := t.PolicyByDigest(e.PolicyDigest)
	if pol == nil || pol.AccountID != e.Scope.ID || pol.Epoch != e.Epoch || pol.AccountKind != e.EnvelopeKind {
		return nil, ErrStale
	}
	if len(e.Signatures) != 1 {
		return nil, ErrSignature
	}
	v := &VerifiedEnvelope{SecretEnvelope: &e, Digest: d, Policy: pol}

	// Signer.
	switch {
	case e.EnvelopeKind == KindManaged && e.SignerRole == RoleBroker:
		v.Signer, err = t.verifyBrokerSig(d, e.Signatures, pol.PoolID, c.New)
	case e.EnvelopeKind == KindManaged: // user-signed enrollment candidate
		v.Signer, err = t.verifyUserSig(d, e.Signatures, c.New)
		if err == nil && !contains(pol.EnrollerPrincipalIDs, v.Signer) {
			err = ErrNotAllowed
		}
		if err == nil && c.New {
			x := c.Enroll
			if x == nil || x.Action.ActionType != ActionEnroll || x.RequesterPrincipalID != v.Signer ||
				x.Action.EnvelopeDigest != d.Hex() || x.Action.SecretVersion != e.SecretVersion || x.Scope != e.Scope {
				err = ErrNoEnroll
			}
		}
	case e.SignerRole == RoleUser: // vaulted
		v.Signer, err = t.verifyUserSig(d, e.Signatures, c.New)
		if err == nil && !contains(pol.AllowedUserPrincipalIDs, v.Signer) {
			err = ErrNotAllowed
		}
	default:
		err = ErrSignerRole
	}
	if err != nil {
		return nil, err
	}

	// Recipients: exactly the rule's set, each wrapped to that recipient's listed key.
	seen := map[string]bool{}
	var users []UUID
	brokers, recovery := 0, 0
	for _, r := range e.Recipients {
		if err := r.shape(); err != nil {
			return nil, err
		}
		if seen[r.RecipientType+"/"+r.RecipientID] {
			return nil, ErrRecipients
		}
		seen[r.RecipientType+"/"+r.RecipientID] = true
		switch r.RecipientType {
		case RecipientBroker:
			if e.EnvelopeKind != KindManaged {
				return nil, ErrRecipients
			}
			if err := t.checkBrokerRecipient(pol.PoolID, r, c.New); err != nil {
				return nil, err
			}
			brokers++
		case RecipientUser:
			if e.EnvelopeKind != KindVaulted {
				return nil, ErrRecipients
			}
			if err := t.checkUserWrap(r, c.New); err != nil {
				return nil, err
			}
			users = append(users, UUID(r.RecipientID))
		case RecipientRecovery:
			rk := t.RecoveryKey()
			if HexID(r.RecipientID) != rk.RecoveryKeyID || r.KeyID != rk.RecoveryKeyID {
				return nil, ErrRecipients
			}
			recovery++
		}
	}
	if e.EnvelopeKind == KindManaged && brokers != 1 {
		return nil, ErrRecipients
	}
	if e.EnvelopeKind == KindVaulted && !sameSet(users, pol.AllowedUserPrincipalIDs) {
		return nil, ErrRecipients
	}
	// Escrow: the recovery recipient iff the sealing policy enables it.
	rk := t.RecoveryKey()
	switch {
	case pol.RecoveryEscrowEnabled && recovery != 1, !pol.RecoveryEscrowEnabled && recovery != 0:
		return nil, ErrRecipients
	case recovery == 0 && e.RecoveryEpoch != 0:
		return nil, ErrRecipients
	case recovery == 1 && (e.RecoveryEpoch < 1 || e.RecoveryEpoch > rk.Epoch || (c.New && e.RecoveryEpoch != rk.Epoch)):
		return nil, ErrRecipients
	}
	return v, nil
}

// verifyBrokerSig requires one signature by a listed pool member; new work needs an active one.
func (t *Trust) verifyBrokerSig(d Digest, sigs []Signature, poolID UUID, active bool) (UUID, error) {
	pool := t.Pool(poolID)
	if pool == nil {
		return "", ErrStale
	}
	ring := keyRing{}
	for _, m := range pool.Members {
		if err := ring.add(RoleBroker, string(m.BrokerID), m.SigPub); err != nil {
			return "", err
		}
	}
	owners, err := verifySigs(d, sigs, ring)
	if err != nil {
		return "", err
	}
	if len(sigs) != 1 {
		return "", ErrSignature
	}
	var id UUID
	for o := range owners[RoleBroker] {
		id = UUID(o)
	}
	if active && pool.Member(id).Status != StatusActive {
		return "", ErrRevoked
	}
	return id, nil
}

// verifyUserSig requires one user signature by a listed key of its principal; new work
// needs an active key.
func (t *Trust) verifyUserSig(d Digest, sigs []Signature, active bool) (UUID, error) {
	if len(sigs) != 1 || sigs[0].SignerRole != RoleUser {
		return "", ErrSignerRole
	}
	for _, r := range t.records {
		ke, ok := r.Manifest.(*KeyEnrollmentManifest)
		if !ok {
			continue
		}
		ring, err := ke.ring(active)
		if err != nil {
			return "", err
		}
		if _, mine := ring[sigs[0].SigKeyID]; mine {
			if _, err := verifySigs(d, sigs, ring); err != nil {
				return "", err
			}
			return ke.PrincipalID, nil
		}
	}
	return "", ErrUnknownKey
}

func (t *Trust) checkBrokerRecipient(poolID UUID, r Recipient, active bool) error {
	pool := t.Pool(poolID)
	if pool == nil {
		return ErrStale
	}
	m := pool.Member(UUID(r.RecipientID))
	if m == nil {
		return ErrRecipients
	}
	if id, _ := EncKeyID(m.EncPub); id != r.KeyID {
		return ErrRecipients
	}
	if active && m.Status != StatusActive {
		return ErrRevoked
	}
	return nil
}

// checkUserWrap requires a user wrap to name a key of its principal; new wraps need an
// active key.
func (t *Trust) checkUserWrap(r Recipient, active bool) error {
	if r.RecipientType != RecipientUser {
		return ErrRecipients
	}
	ke := t.Enrollment(UUID(r.RecipientID))
	if ke == nil {
		return ErrRecipients
	}
	for _, k := range ke.Keys {
		if k.EncKeyID == r.KeyID && (!active || k.Status == StatusActive) {
			return nil
		}
	}
	return ErrRecipients
}

func sameSet(a, b []UUID) bool {
	if len(a) != len(b) || distinct(a) != nil {
		return false
	}
	for _, x := range a {
		if !contains(b, x) {
			return false
		}
	}
	return true
}
