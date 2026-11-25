package pqcrypto

// Receipt types and abort reasons (§3.5).
const (
	ReceiptCommitTarget = "commit_target"
	ReceiptAbort        = "abort"
	ReceiptVaultCommit  = "vault_commit"
	ReceiptRelease      = "release"
	ReceiptRewrapUser   = "rewrap_user"

	ReasonRefused           = "refused"
	ReasonRestartBeforeSend = "restart_before_send"
	ReasonEnrollmentFailed  = "enrollment_failed"
	ReasonSuperseded        = "superseded_by_reenrollment"
)

// EnvelopeReceipt is type receipt, account scope; its epoch is the policy epoch at append.
type EnvelopeReceipt struct {
	Header
	EnvelopeID      UUID        `json:"envelope_id"`
	EnvelopeKind    string      `json:"envelope_kind"`
	SecretVersion   Counter     `json:"secret_version"`
	ReceiptSeq      Counter     `json:"receipt_seq"`
	PrevReceiptHash HexID       `json:"prev_receipt_hash"`
	ReceiptType     string      `json:"receipt_type"`
	Reason          string      `json:"reason,omitzero"`
	OperationID     UUID        `json:"operation_id"`
	ExtraRecipients []Recipient `json:"extra_recipients"`
	IssuedAt        Time        `json:"issued_at"`
	Sigs
}

// Chain is the verified state of one envelope's receipt chain.
type Chain struct {
	Envelope *VerifiedEnvelope
	Seq      Counter
	Head     HexID // D of the last receipt; ZeroHex before seq 1
	Heads    []HexID
	// Terminal and evidence flags.
	CommitTarget, Released, VaultCommitted, Aborted bool
	users                                           map[UUID]bool // user recipients so far
}

// NewChain starts the chain of a verified envelope.
func NewChain(e *VerifiedEnvelope) *Chain {
	c := &Chain{Envelope: e, Head: ZeroHex, users: map[UUID]bool{}}
	for _, r := range e.Recipients {
		if r.RecipientType == RecipientUser {
			c.users[UUID(r.RecipientID)] = true
		}
	}
	return c
}

// Unterminated reports no release, no vault_commit and no abort.
func (c *Chain) Unterminated() bool { return !c.Released && !c.VaultCommitted && !c.Aborted }

// Current reports whether this envelope can be the account's current envelope (§3.5):
// managed needs release or a chain beginning with vault_commit; vaulted needs vault_commit.
func (c *Chain) Current() bool {
	if c.Envelope.EnvelopeKind == KindManaged {
		return c.Released || c.VaultCommitted
	}
	return c.VaultCommitted
}

// CurrentEnvelopeOf applies the current-envelope rule: the highest secret_version whose
// chain qualifies. It returns nil if none does.
func CurrentEnvelopeOf(chains []*Chain) *Chain {
	var best *Chain
	for _, c := range chains {
		if c.Current() && (best == nil || c.Envelope.SecretVersion > best.Envelope.SecretVersion) {
			best = c
		}
	}
	return best
}

// ReceiptContext says how a receipt is being used.
type ReceiptContext struct {
	// New is true for a receipt being appended now: its signer must be an active member or
	// key, and its epoch the current policy epoch. False verifies history.
	New bool
	// StandingRelease is the verified standing_release a managed rewrap_user executes.
	StandingRelease *AccessTransaction
}

// Append verifies the next receipt against the chain (§3.5 receipt rules, compare-and-swap
// on seq and previous hash) and advances it. The chain is unchanged on error.
func (t *Trust) Append(c *Chain, raw []byte, rc ReceiptContext) (*EnvelopeReceipt, error) {
	var r EnvelopeReceipt
	_, d, err := decodeSigned(raw, &r)
	if err != nil {
		return nil, err
	}
	e := c.Envelope
	if r.Type != TypeReceipt || r.Scope != e.Scope || (r.SignerRole != RoleBroker && r.SignerRole != RoleUser) {
		return nil, ErrHeader
	}
	if r.DeploymentID != t.deployment {
		return nil, ErrDeployment
	}
	if r.EnvelopeID != e.EnvelopeID || r.EnvelopeKind != e.EnvelopeKind || r.SecretVersion != e.SecretVersion ||
		!r.OperationID.Valid() || r.ExtraRecipients == nil {
		return nil, ErrReceipt
	}
	if r.ReceiptSeq != c.Seq+1 || r.PrevReceiptHash != c.Head {
		return nil, ErrChain // fork, gap or replay at another position
	}
	if c.Aborted {
		return nil, ErrChain // abort is terminal
	}
	cur, _ := t.Policy(e.Scope.ID)
	if cur == nil || r.Epoch < e.Epoch || (rc.New && r.Epoch != cur.Epoch) {
		return nil, ErrStale
	}
	if (r.Reason != "") != (r.ReceiptType == ReceiptAbort) {
		return nil, ErrReceipt
	}

	// Signer.
	var signer UUID
	if r.SignerRole == RoleBroker {
		signer, err = t.verifyBrokerSig(d, r.Signatures, e.Policy.PoolID, rc.New)
	} else {
		signer, err = t.verifyUserSig(d, r.Signatures, rc.New)
	}
	if err != nil {
		return nil, err
	}
	broker := r.SignerRole == RoleBroker
	managed := e.EnvelopeKind == KindManaged
	first := r.ReceiptSeq == 1
	noExtra := len(r.ExtraRecipients) == 0

	switch r.ReceiptType {
	case ReceiptCommitTarget:
		if !managed || !e.RotationEnvelope() || !first || !broker || !noExtra {
			return nil, ErrReceipt
		}
	case ReceiptAbort:
		if !managed || !broker || !noExtra || !c.Unterminated() {
			return nil, ErrReceipt
		}
		switch r.Reason {
		case ReasonRefused, ReasonRestartBeforeSend:
			if !first || !e.RotationEnvelope() {
				return nil, ErrReceipt
			}
		case ReasonEnrollmentFailed:
			if !first || e.RotationEnvelope() {
				return nil, ErrReceipt
			}
		case ReasonSuperseded:
		default:
			return nil, ErrReceipt
		}
	case ReceiptVaultCommit:
		if !first || !noExtra {
			return nil, ErrReceipt
		}
		if managed && (!broker || e.RotationEnvelope()) {
			return nil, ErrReceipt // managed: the pool broker, on an enrollment candidate
		}
		if !managed && (broker || signer != e.Signer || !contains(cur.AllowedUserPrincipalIDs, signer)) {
			return nil, ErrReceipt // vaulted: the sealing user, still allowed
		}
	case ReceiptRelease:
		if !managed || !broker || !e.RotationEnvelope() || !c.CommitTarget || c.Released {
			return nil, ErrReceipt
		}
		var want []UUID
		if e.Policy.CheckoutMode == ModeStanding && e.Policy.AutoStandingRelease != nil && *e.Policy.AutoStandingRelease {
			want = e.Policy.StandingRecipientPrincipalIDs
		}
		if err := t.checkExtra(r.ExtraRecipients, want, rc.New); err != nil {
			return nil, err
		}
	case ReceiptRewrapUser:
		if !c.Released && !c.VaultCommitted {
			return nil, ErrReceipt // never before release or vault_commit
		}
		var want []UUID
		for _, x := range r.ExtraRecipients {
			want = append(want, UUID(x.RecipientID))
		}
		if len(want) == 0 {
			return nil, ErrReceipt
		}
		if managed {
			if !broker {
				return nil, ErrReceipt
			}
			if rc.New {
				x := rc.StandingRelease
				if x == nil || x.Action.ActionType != ActionStandingRelease || x.Action.EnvelopeID != e.EnvelopeID ||
					x.Action.ReceiptHeadHash != c.Head || !sameSet(want, x.Action.RecipientPrincipalIDs) {
					return nil, ErrNotAllowed
				}
			}
		} else {
			if broker || !c.users[signer] || !contains(cur.AllowedUserPrincipalIDs, signer) {
				return nil, ErrReceipt
			}
			for _, p := range want {
				if !contains(cur.AllowedUserPrincipalIDs, p) {
					return nil, ErrNotAllowed
				}
			}
		}
		if err := t.checkExtra(r.ExtraRecipients, want, rc.New); err != nil {
			return nil, err
		}
	default:
		return nil, ErrReceipt
	}

	c.Seq, c.Head = r.ReceiptSeq, d.Hex()
	c.Heads = append(c.Heads, c.Head)
	switch r.ReceiptType {
	case ReceiptCommitTarget:
		c.CommitTarget = true
	case ReceiptAbort:
		c.Aborted = true
	case ReceiptVaultCommit:
		c.VaultCommitted = true
	case ReceiptRelease:
		c.Released = true
	}
	for _, x := range r.ExtraRecipients {
		c.users[UUID(x.RecipientID)] = true
	}
	return &r, nil
}

// checkExtra requires exactly one user wrap per wanted principal, each to a key of it.
func (t *Trust) checkExtra(extra []Recipient, want []UUID, active bool) error {
	var got []UUID
	for _, x := range extra {
		if err := x.shape(); err != nil {
			return err
		}
		if err := t.checkUserWrap(x, active); err != nil {
			return err
		}
		got = append(got, UUID(x.RecipientID))
	}
	if !sameSet(got, want) {
		return ErrRecipients
	}
	return nil
}

// ChainExtends reports whether remote is local plus zero or more receipts. The broker
// refuses any Control Plane chain that is older than or diverges from its own copy (§3.7).
func ChainExtends(local, remote []HexID) error {
	if len(remote) < len(local) {
		return ErrChain
	}
	for i := range local {
		if local[i] != remote[i] {
			return ErrChain
		}
	}
	return nil
}
