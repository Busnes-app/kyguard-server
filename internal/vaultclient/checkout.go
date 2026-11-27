package vaultclient

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Checkout is a signed vault_checkout transaction and the fresh cnf key that must sign its
// possession proofs (§3.6 step 1). The cnf key never leaves the client.
type Checkout struct {
	RequestID pqcrypto.UUID
	Tx        []byte
	Cnf       *pqcrypto.SigningKey
}

// NewTransaction signs an access transaction for the account's current verified policy and
// active broker, with a fresh cnf key. a carries the action fields; the account and
// descriptor digest are filled in.
func NewTransaction(tr *pqcrypto.Trust, a pqcrypto.Action, principal pqcrypto.UUID, key *pqcrypto.SigningKey, now time.Time) (*Checkout, error) {
	pol, pd := tr.Policy(a.AccountID)
	if pol == nil || pol.AccountKind != pqcrypto.KindManaged {
		return nil, errors.New("kyguard: no verified managed policy for the account")
	}
	pool := tr.Pool(pol.PoolID)
	if pool == nil || pool.Active() == nil {
		return nil, errors.New("kyguard: the account's pool has no active broker")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	cnf, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	a.TargetDescriptorDigest = pol.TargetDescriptorDigest
	tx := &pqcrypto.AccessTransaction{Header: pqcrypto.Header{Type: pqcrypto.TypeTx, DeploymentID: tr.DeploymentID(), Epoch: pol.Epoch,
		Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: a.AccountID}, SignerRole: pqcrypto.RoleUser},
		RequestID: pqcrypto.UUID(id.String()), RequesterPrincipalID: principal, BrokerID: pool.Active().BrokerID, PolicyDigest: pd.Hex(),
		CnfPub: cnf.Public(), IssuedAt: pqcrypto.NewTime(now), ExpiresAt: pqcrypto.NewTime(now.Add(pqcrypto.MaxTxLifetime)),
		Action: a, Approvals: []pqcrypto.Approval{}}
	if err := pqcrypto.Sign(tx, pqcrypto.RoleUser, key); err != nil {
		return nil, err
	}
	raw, err := canonical.Marshal(tx)
	if err != nil {
		return nil, err
	}
	return &Checkout{RequestID: tx.RequestID, Tx: raw, Cnf: cnf}, nil
}

// Proof signs a possession proof over the transaction's digest and the broker's challenge.
func (c *Checkout) Proof(challenge []byte, purpose string) ([]byte, error) {
	var tx pqcrypto.AccessTransaction
	if _, err := canonical.Decode(c.Tx, &tx); err != nil {
		return nil, err
	}
	d, err := pqcrypto.ObjDigest(&tx)
	if err != nil {
		return nil, err
	}
	p := &pqcrypto.PossessionProof{Header: pqcrypto.Header{Type: pqcrypto.TypePoP, DeploymentID: tx.DeploymentID, Epoch: tx.Epoch, Scope: tx.Scope, SignerRole: pqcrypto.RoleCnf},
		TxDigest: d.Hex(), Purpose: purpose, BrokerChallenge: challenge}
	if err := pqcrypto.Sign(p, pqcrypto.RoleCnf, c.Cnf); err != nil {
		return nil, err
	}
	return canonical.Marshal(p)
}

// OpenDelivery opens a checkout wrap: it verifies the account's current envelope against the
// CLI's trust, unwraps the DEK the broker sealed to this user's key and decrypts locally
// (§3.6 step 4). The caller wipes the result.
func OpenDelivery(tr *pqcrypto.Trust, envelope []byte, wrap pqcrypto.Recipient, sk recoverykey.PrivateKey) ([]byte, error) {
	v, err := tr.VerifyEnvelope(envelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return nil, err
	}
	if wrap.RecipientType != pqcrypto.RecipientUser {
		return nil, pqcrypto.ErrRecipients
	}
	dek, err := pqcrypto.UnwrapDEK(sk, v.RecipientAAD(wrap), wrap.Enc, wrap.WrappedDEK)
	if err != nil {
		return nil, err
	}
	defer clear(dek)
	return v.OpenPassword(dek)
}
