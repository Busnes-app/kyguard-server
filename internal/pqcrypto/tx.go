package pqcrypto

import (
	"crypto/subtle"
	"time"
)

// Errors returned by the transaction, envelope and receipt rules.
const (
	ErrAction     Error = "unknown_action_type"
	ErrExpired    Error = "outside_validity"
	ErrNotAllowed Error = "principal_not_allowed"
	ErrApprovals  Error = "approvals_not_met"
	ErrReplay     Error = "request_replayed"
	ErrStale      Error = "stale_reference"
	ErrRecipients Error = "invalid_recipient_set"
	ErrRevoked    Error = "revoked_member"
	ErrChain      Error = "invalid_receipt_chain"
	ErrReceipt    Error = "invalid_receipt"
	ErrNoEnroll   Error = "no_matching_enroll"
)

// Action types (§3.4). Any other value is rejected.
const (
	ActionVaultCheckout   = "vault_checkout"
	ActionStandingRelease = "standing_release"
	ActionManualRotation  = "manual_rotation"
	ActionEnroll          = "enroll"
)

// MaxTxLifetime bounds expires_at - issued_at.
const MaxTxLifetime = 10 * time.Minute

// Action is the action of an AccessTransaction. Only the fields of its action_type are
// present; any other field present rejects the transaction.
type Action struct {
	ActionType             string  `json:"action_type"`
	AccountID              UUID    `json:"account_id"`
	TargetDescriptorDigest HexID   `json:"target_descriptor_digest"`
	SecretVersion          Counter `json:"secret_version,omitzero"`
	EncKeyID               HexID   `json:"enc_key_id,omitzero"`
	CheckoutTTLSeconds     int64   `json:"checkout_ttl_seconds,omitzero"`
	EnvelopeID             UUID    `json:"envelope_id,omitzero"`
	ReceiptHeadHash        HexID   `json:"receipt_head_hash,omitzero"`
	RecipientPrincipalIDs  []UUID  `json:"recipient_principal_ids,omitzero"`
	EnvelopeDigest         HexID   `json:"envelope_digest,omitzero"`
}

// present lists which optional fields are set, in a fixed order.
func (a *Action) present() string {
	s := ""
	for _, f := range []struct {
		c  string
		on bool
	}{{"v", a.SecretVersion != 0}, {"k", a.EncKeyID != ""}, {"t", a.CheckoutTTLSeconds != 0},
		{"e", a.EnvelopeID != ""}, {"h", a.ReceiptHeadHash != ""}, {"r", a.RecipientPrincipalIDs != nil},
		{"d", a.EnvelopeDigest != ""}} {
		if f.on {
			s += f.c
		}
	}
	return s
}

// actionFields is the exact optional field set of each action type.
var actionFields = map[string]string{
	ActionVaultCheckout:   "vkt",
	ActionStandingRelease: "ehr",
	ActionManualRotation:  "",
	ActionEnroll:          "vd",
}

// Approval is an approver's signature over D(tx); approvals are outside D.
type Approval struct {
	ApproverPrincipalID UUID      `json:"approver_principal_id"`
	SigKeyID            HexID     `json:"sig_key_id"`
	Sig                 HybridSig `json:"sig"`
}

// AccessTransaction is type tx, account scope; its epoch is the referenced policy epoch.
type AccessTransaction struct {
	Header
	RequestID            UUID       `json:"request_id"`
	RequesterPrincipalID UUID       `json:"requester_principal_id"`
	BrokerID             UUID       `json:"broker_id"`
	PolicyDigest         HexID      `json:"policy_digest"`
	CnfPub               HybridPub  `json:"cnf_pub"`
	IssuedAt             Time       `json:"issued_at"`
	ExpiresAt            Time       `json:"expires_at"`
	Action               Action     `json:"action"`
	Approvals            []Approval `json:"approvals"`
	Sigs
}

// Approve appends an approval by principal with key k.
func (tx *AccessTransaction) Approve(principal UUID, k *SigningKey) error {
	d, err := ObjDigest(tx)
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
	tx.Approvals = append(tx.Approvals, Approval{principal, id, sig})
	return nil
}

// CurrentEnvelope is the broker's view of an account's current envelope (§3.5).
type CurrentEnvelope struct {
	EnvelopeID    UUID
	SecretVersion Counter
	ReceiptHead   HexID
}

// TxContext is the broker state a transaction is checked against.
type TxContext struct {
	BrokerID       UUID
	Now            time.Time
	Seen           func(requestID UUID) bool // burned request IDs
	Current        *CurrentEnvelope          // nil when the account has none
	HighestVersion Counter                   // highest secret_version the broker has seen
	// Candidate is the enrollment candidate the Control Plane relayed and its reserved version.
	CandidateDigest  HexID
	CandidateVersion Counter
	// AllowPartialApprovals is for collecting signatures. Broker and API admission always require quorum.
	AllowPartialApprovals bool
}

// VerifyTx applies the broker's transaction checks of §3.4 in order, except the journal
// state checks (open rotations and leases), which belong to the broker. It returns the
// decoded transaction and D(tx).
func (t *Trust) VerifyTx(raw []byte, c TxContext) (*AccessTransaction, Digest, error) {
	var tx AccessTransaction
	_, d, err := decodeSigned(raw, &tx)
	if err != nil {
		return nil, Digest{}, err
	}
	if err := checkHeader(&tx.Header, TypeTx, ScopeAccount, RoleUser); err != nil {
		return nil, d, err
	}
	a := &tx.Action
	want, known := actionFields[a.ActionType]
	if !known {
		return nil, d, ErrAction
	}
	if a.present() != want || tx.Approvals == nil || tx.Scope.ID != a.AccountID || !v7(tx.RequestID) {
		return nil, d, ErrBody
	}
	if _, err := tx.CnfPub.SigKeyID(); err != nil {
		return nil, d, ErrBody
	}

	// 1. Deployment, broker, current policy, descriptor and validity window.
	if tx.DeploymentID != t.deployment {
		return nil, d, ErrDeployment
	}
	pol, pd := t.Policy(a.AccountID)
	if pol == nil || pol.AccountKind != KindManaged {
		return nil, d, ErrStale
	}
	pool := t.Pool(pol.PoolID)
	if tx.BrokerID != c.BrokerID || pool == nil || pool.Active() == nil || pool.Active().BrokerID != c.BrokerID {
		return nil, d, ErrNotAllowed
	}
	if tx.Epoch != pol.Epoch || tx.PolicyDigest != pd.Hex() || a.TargetDescriptorDigest != pol.TargetDescriptorDigest {
		return nil, d, ErrStale
	}
	if tx.ExpiresAt.Sub(tx.IssuedAt.Time) > MaxTxLifetime || c.Now.Before(tx.IssuedAt.Time) || !c.Now.Before(tx.ExpiresAt.Time) {
		return nil, d, ErrExpired
	}

	// 2. Requester signature under an active enrolled key, and requester authorization.
	if err := t.verifyPrincipalSig(d, tx.Signatures, tx.RequesterPrincipalID); err != nil {
		return nil, d, err
	}
	allowed := pol.AllowedUserPrincipalIDs
	if a.ActionType == ActionEnroll {
		allowed = pol.EnrollerPrincipalIDs
	}
	if !contains(allowed, tx.RequesterPrincipalID) {
		return nil, d, ErrNotAllowed
	}

	// 3. Approvals: distinct allowed approvers other than the requester.
	approvers := map[UUID]bool{}
	for _, ap := range tx.Approvals {
		if ap.ApproverPrincipalID == tx.RequesterPrincipalID || approvers[ap.ApproverPrincipalID] ||
			!contains(pol.AllowedApproverPrincipalIDs, ap.ApproverPrincipalID) {
			return nil, d, ErrApprovals
		}
		if err := t.verifyPrincipalSig(d, []Signature{{RoleUser, ap.SigKeyID, ap.Sig}}, ap.ApproverPrincipalID); err != nil {
			return nil, d, err
		}
		approvers[ap.ApproverPrincipalID] = true
	}
	if !c.AllowPartialApprovals && len(approvers) < pol.RequiredApproverCount {
		return nil, d, ErrApprovals
	}

	// 4. Replay.
	if c.Seen == nil || c.Seen(tx.RequestID) {
		return nil, d, ErrReplay
	}

	// 5. Action checks.
	switch a.ActionType {
	case ActionVaultCheckout:
		if pol.CheckoutMode != ModeEphemeral {
			return nil, d, ErrNotAllowed
		}
		if c.Current == nil || a.SecretVersion != c.Current.SecretVersion {
			return nil, d, ErrStale
		}
		if ke := t.Enrollment(tx.RequesterPrincipalID); ke == nil || ke.ActiveEncKey(a.EncKeyID) == nil {
			return nil, d, ErrNotAllowed
		}
		if a.CheckoutTTLSeconds < 1 || a.CheckoutTTLSeconds > pol.MaxCheckoutTTLSeconds {
			return nil, d, ErrNotAllowed
		}
	case ActionStandingRelease:
		if pol.CheckoutMode != ModeStanding {
			return nil, d, ErrNotAllowed
		}
		if c.Current == nil || a.EnvelopeID != c.Current.EnvelopeID || a.ReceiptHeadHash != c.Current.ReceiptHead {
			return nil, d, ErrStale
		}
		if len(a.RecipientPrincipalIDs) == 0 || distinct(a.RecipientPrincipalIDs) != nil {
			return nil, d, ErrBody
		}
		for _, p := range a.RecipientPrincipalIDs {
			ke := t.Enrollment(p)
			if !contains(pol.StandingRecipientPrincipalIDs, p) || ke == nil || !ke.HasActiveEncKey() {
				return nil, d, ErrNotAllowed
			}
		}
	case ActionEnroll:
		if a.EnvelopeDigest != c.CandidateDigest || a.SecretVersion != c.CandidateVersion || c.CandidateDigest == "" {
			return nil, d, ErrStale
		}
		if a.SecretVersion <= c.HighestVersion {
			return nil, d, ErrStale
		}
	}
	return &tx, d, nil
}

// verifyPrincipalSig requires exactly one signature, by an active key of the principal.
func (t *Trust) verifyPrincipalSig(d Digest, sigs []Signature, principal UUID) error {
	ke := t.Enrollment(principal)
	if ke == nil {
		return ErrUnknownKey
	}
	ring, err := ke.ring(true)
	if err != nil {
		return err
	}
	if len(sigs) != 1 {
		return ErrSignature
	}
	_, err = verifySigs(d, sigs, ring)
	return err
}

// PoP purposes.
const (
	PurposeDeliver = "deliver"
	PurposeCheckin = "checkin"
)

// ChallengeBytes is the size of a broker challenge.
const ChallengeBytes = 32

// PossessionProof is type pop, signed by the transaction's cnf_pub (§3.4).
type PossessionProof struct {
	Header
	TxDigest        HexID  `json:"tx_digest"`
	Purpose         string `json:"purpose"`
	BrokerChallenge B64    `json:"broker_challenge"`
	Sigs
}

// VerifyPoP checks a possession proof against a verified transaction, the challenge this
// broker issued and the purpose it expects. Single use of the challenge is the caller's.
func VerifyPoP(raw []byte, tx *AccessTransaction, txDigest Digest, challenge []byte, purpose string) (*PossessionProof, error) {
	var p PossessionProof
	_, d, err := decodeSigned(raw, &p)
	if err != nil {
		return nil, err
	}
	if err := checkHeader(&p.Header, TypePoP, ScopeAccount, RoleCnf); err != nil {
		return nil, err
	}
	if p.DeploymentID != tx.DeploymentID || p.Scope != tx.Scope || p.Epoch != tx.Epoch {
		return nil, ErrStale
	}
	if p.TxDigest != txDigest.Hex() || p.Purpose != purpose ||
		len(challenge) != ChallengeBytes || subtle.ConstantTimeCompare(p.BrokerChallenge, challenge) != 1 {
		return nil, ErrStale
	}
	ring := keyRing{}
	if err := ring.add(RoleCnf, "cnf", tx.CnfPub); err != nil {
		return nil, err
	}
	if len(p.Signatures) != 1 {
		return nil, ErrSignature
	}
	if _, err := verifySigs(d, p.Signatures, ring); err != nil {
		return nil, err
	}
	return &p, nil
}

func contains(l []UUID, id UUID) bool {
	for _, x := range l {
		if x == id {
			return true
		}
	}
	return false
}

// v7 reports whether u is a version-7 UUID.
func v7(u UUID) bool { return u.Valid() && u[14] == '7' }
