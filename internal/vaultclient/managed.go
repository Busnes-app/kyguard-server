package vaultclient

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Enrollment is a sealed managed enrollment candidate and the enroll transaction over it
// (spec §4.5 step 2).
type Enrollment struct {
	Tx       []byte
	Envelope []byte
}

// ErrNotEnroller means the current policy does not let this principal enroll the account.
var ErrNotEnroller = errors.New("kyguard: principal is not an enroller of this account")

// SealEnrollment seals password as a managed candidate to the account's active broker (and
// the recovery key when the current policy escrows), signs it as the user, and signs an
// enroll transaction over its digest and the reserved version. Everything comes from the
// CLI's own verified trust state, never from the Control Plane.
func SealEnrollment(tr *pqcrypto.Trust, account, requestID pqcrypto.UUID, version pqcrypto.Counter, principal pqcrypto.UUID, key *pqcrypto.SigningKey, password []byte, now time.Time) (*Enrollment, error) {
	pol, pd := tr.Policy(account)
	if pol == nil || pol.AccountKind != pqcrypto.KindManaged {
		return nil, errors.New("kyguard: no verified managed policy for the account")
	}
	if !contains(pol.EnrollerPrincipalIDs, principal) {
		return nil, ErrNotEnroller
	}
	pool := tr.Pool(pol.PoolID)
	if pool == nil || pool.Active() == nil {
		return nil, errors.New("kyguard: the account's pool has no active broker")
	}
	b := pool.Active()
	to := []pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(b.BrokerID), Pub: b.EncPub}}
	recoveryEpoch := pqcrypto.Counter(0)
	if pol.RecoveryEscrowEnabled {
		rk := tr.RecoveryKey()
		to = append(to, pqcrypto.SealTo{Type: pqcrypto.RecipientRecovery, ID: string(rk.RecoveryKeyID), Pub: rk.RecoveryPubkey})
		recoveryEpoch = rk.Epoch
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	scope := pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: account}
	env, err := pqcrypto.Seal(pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: tr.DeploymentID(), Epoch: pol.Epoch, Scope: scope, SignerRole: pqcrypto.RoleUser},
		pqcrypto.KindManaged, pqcrypto.UUID(id.String()), version, pd.Hex(), recoveryEpoch, now, password, to)
	if err != nil {
		return nil, err
	}
	if err := pqcrypto.Sign(env, pqcrypto.RoleUser, key); err != nil {
		return nil, err
	}
	envRaw, err := canonical.Marshal(env)
	if err != nil {
		return nil, err
	}
	ed, err := pqcrypto.ObjDigest(env)
	if err != nil {
		return nil, err
	}
	cnf, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		return nil, err
	}
	tx := &pqcrypto.AccessTransaction{Header: pqcrypto.Header{Type: pqcrypto.TypeTx, DeploymentID: tr.DeploymentID(), Epoch: pol.Epoch, Scope: scope, SignerRole: pqcrypto.RoleUser},
		RequestID: requestID, RequesterPrincipalID: principal, BrokerID: b.BrokerID, PolicyDigest: pd.Hex(), CnfPub: cnf.Public(),
		IssuedAt: pqcrypto.NewTime(now), ExpiresAt: pqcrypto.NewTime(now.Add(pqcrypto.MaxTxLifetime)),
		Action: pqcrypto.Action{ActionType: pqcrypto.ActionEnroll, AccountID: account, TargetDescriptorDigest: pol.TargetDescriptorDigest,
			EnvelopeDigest: ed.Hex(), SecretVersion: version},
		Approvals: []pqcrypto.Approval{}}
	if err := pqcrypto.Sign(tx, pqcrypto.RoleUser, key); err != nil {
		return nil, err
	}
	txRaw, err := canonical.Marshal(tx)
	if err != nil {
		return nil, err
	}
	return &Enrollment{Tx: txRaw, Envelope: envRaw}, nil
}

func contains(l []pqcrypto.UUID, id pqcrypto.UUID) bool {
	for _, x := range l {
		if x == id {
			return true
		}
	}
	return false
}

// SignReservation signs the request to reserve an enrollment as an enroller's active key.
func SignReservation(tr *pqcrypto.Trust, account, requestID, principal pqcrypto.UUID, key *pqcrypto.SigningKey, now time.Time) (*pqcrypto.EnrollReservation, error) {
	r := &pqcrypto.EnrollReservation{DeploymentID: tr.DeploymentID(), AccountID: account, RequestID: requestID, PrincipalID: principal, IssuedAt: pqcrypto.NewTime(now)}
	d, err := r.Digest()
	if err != nil {
		return nil, err
	}
	if r.Sig, err = key.Sign(d); err != nil {
		return nil, err
	}
	r.SigKeyID, err = key.Public().SigKeyID()
	return r, err
}
