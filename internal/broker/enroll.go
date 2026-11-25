package broker

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// ErrEnrollmentOpen means another enrollment of the account has not finished.
var ErrEnrollmentOpen = errors.New("broker: an enrollment of this account is still open")

// Enroll takes a relayed enroll transaction and its candidate (§3.4, §4.5). Everything that
// can be refused is refused before anything is journaled or any target is touched: the
// transaction checks, the account state and the candidate's signer and recipients.
func (m *Machine) Enroll(ctx context.Context, txRaw, envRaw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var head struct {
		Scope pqcrypto.Scope `json:"scope"`
	}
	if err := json.Unmarshal(txRaw, &head); err != nil {
		return pqcrypto.ErrHeader
	}
	a, err := m.J.Account(head.Scope.ID)
	if err != nil {
		return err
	}
	var cand pqcrypto.SecretEnvelope
	if _, err := canonical.Decode(envRaw, &cand); err != nil {
		return err
	}
	cd, err := pqcrypto.ObjDigest(&cand)
	if err != nil {
		return err
	}
	tc := pqcrypto.TxContext{BrokerID: m.ID, Now: m.now(), Seen: m.J.Burned, HighestVersion: a.HighestVersion,
		CandidateDigest: cd.Hex(), CandidateVersion: cand.SecretVersion}
	tx, _, err := m.Trust.VerifyTx(txRaw, tc)
	if err != nil {
		return err
	}
	if tx.Action.ActionType != pqcrypto.ActionEnroll {
		return pqcrypto.ErrAction
	}
	// §3.4 step 5: quarantined, or no open rotation; one enrollment at a time.
	if a.Run.Open() && !a.Quarantined {
		return ErrBlocked
	}
	if a.Enrollment.Open() {
		return ErrEnrollmentOpen
	}
	if _, err := m.Trust.VerifyEnvelope(envRaw, pqcrypto.EnvelopeContext{New: true, Enroll: tx}); err != nil {
		return err
	}
	op, err := pqcrypto.RequestOpID(tx.RequestID, 0)
	if err != nil {
		return err
	}
	a.Enrollment = &Enrollment{OperationID: op, Tx: txRaw, Candidate: envRaw}
	a.HighestVersion = cand.SecretVersion
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("enroll_journaled"); err != nil {
		return err
	}
	return m.acceptEnrollment(ctx, a, tx)
}

// acceptEnrollment asks the Control Plane to mark the reservation accepted. Without that
// acknowledgement the broker never binds and the attempt fails (§4.5 step 2).
func (m *Machine) acceptEnrollment(ctx context.Context, a *Account, tx *pqcrypto.AccessTransaction) error {
	if err := m.CP.Accept(ctx, a.ID, a.Enrollment.OperationID); err != nil {
		return m.enrollFail(ctx, a)
	}
	a.Enrollment.AcceptAck = true
	if err := m.J.SaveBurn(a, tx.RequestID, tx.ExpiresAt.Time); err != nil {
		return err
	}
	if err := m.hook("accept_ack"); err != nil {
		return err
	}
	return m.verifyEnrollment(ctx, a)
}

// verifyEnrollment journals the start of the one verification, then binds once with the
// candidate at the pinned target and reads the minimum password age.
func (m *Machine) verifyEnrollment(ctx context.Context, a *Account) error {
	a.Enrollment.VerifyStarted = true
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("verify_started"); err != nil {
		return err
	}
	cand, err := m.Trust.VerifyEnvelope(a.Enrollment.Candidate, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	rc, err := m.target(a)
	if err != nil {
		return m.enrollFail(ctx, a)
	}
	pw, err := m.open(cand.SecretEnvelope)
	if err != nil {
		return m.enrollFail(ctx, a)
	}
	s, err := rc.conn.Login(ctx, rc.target, pw)
	clear(pw)
	a.Enrollment.VerifyDone = true
	if err != nil {
		return m.enrollFail(ctx, a)
	}
	if ar, ok := s.(AgeReporter); ok {
		if last, minAge, err := ar.PasswordAge(ctx); err == nil {
			a.MinAgeSeconds, a.MinAgeDeadline = int64(minAge/time.Second), last.Add(minAge)
		}
	}
	s.Close()
	a.Enrollment.Verified = true
	return m.enrollCommit(ctx, a, cand)
}

// target is the account's verified descriptor and connector.
func (m *Machine) target(a *Account) (*rotationContext, error) {
	p, _ := m.Trust.Policy(a.ID)
	if p == nil {
		return nil, ErrNotActive
	}
	raw := m.J.Descriptor(p.TargetDescriptorDigest)
	if raw == nil {
		return nil, ErrNoDescriptor
	}
	td, dg, err := pqcrypto.DecodeTargetDescriptor(raw)
	if err != nil || dg.Hex() != p.TargetDescriptorDigest {
		return nil, ErrNoDescriptor
	}
	conn := m.Connectors[td.ConnectorType]
	if conn == nil {
		return nil, ErrNoDescriptor
	}
	return &rotationContext{policy: p, target: td, conn: conn}, nil
}

// enrollCommit, in one journal transaction, voids any stuck intent, signs abort
// (superseded_by_reenrollment) at the next sequence number of every unterminated envelope,
// and signs vault_commit for the candidate (§4.5 step 3); then it delivers them.
func (m *Machine) enrollCommit(ctx context.Context, a *Account, cand *pqcrypto.VerifiedEnvelope) error {
	// A stuck run's envelope was stored at the Control Plane but never joined the copy.
	if a.Run.Open() && !a.Run.Sent {
		a.Chains = append(a.Chains, ChainCopy{Envelope: a.Run.NewEnvelope, Receipts: []pqcrypto.B64{}})
	}
	chains, err := m.chains(a)
	if err != nil {
		return err
	}
	op := a.Enrollment.OperationID
	var receipts []pqcrypto.B64
	for _, ch := range chains {
		if !ch.Unterminated() || ch.Envelope.EnvelopeID == cand.EnvelopeID {
			continue
		}
		r, err := m.receipt(ch, op, pqcrypto.ReceiptAbort, pqcrypto.ReasonSuperseded)
		if err != nil {
			return err
		}
		receipts = append(receipts, r)
	}
	vc, err := m.receipt(pqcrypto.NewChain(cand), op, pqcrypto.ReceiptVaultCommit, "")
	if err != nil {
		return err
	}
	receipts = append(receipts, vc)
	if a.Run.Open() {
		a.Run.State, a.Run.Reason = StateAborted, pqcrypto.ReasonSuperseded
	}
	a.Quarantined, a.Health, a.HealthReason = false, HealthHealthy, ""
	a.CurrentCommitAt, a.Refusals, a.NextAttemptAt = m.now(), 0, time.Time{}
	a.Enrollment.Receipts = receipts
	if err := m.J.Save(a); err != nil {
		return err
	}
	return m.enrollSend(ctx, a)
}

// enrollFail appends abort (enrollment_failed) to the candidate only; the account is
// otherwise unchanged, and a quarantined account stays quarantined (§4.5 step 4).
func (m *Machine) enrollFail(ctx context.Context, a *Account) error {
	cand, err := m.Trust.VerifyEnvelope(a.Enrollment.Candidate, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	r, err := m.receipt(pqcrypto.NewChain(cand), a.Enrollment.OperationID, pqcrypto.ReceiptAbort, pqcrypto.ReasonEnrollmentFailed)
	if err != nil {
		return err
	}
	a.Enrollment.Receipts = []pqcrypto.B64{r}
	if err := m.J.Save(a); err != nil {
		return err
	}
	return m.enrollSend(ctx, a)
}

// enrollSend delivers the receipts until acknowledged, then merges them into the broker's
// copy of the account's chains.
func (m *Machine) enrollSend(ctx context.Context, a *Account) error {
	if err := m.hook("before_enroll_send"); err != nil {
		return err
	}
	e := a.Enrollment
	if err := m.CP.Receipts(ctx, e.OperationID, a.ID, e.Receipts); err != nil {
		return err
	}
	e.Sent = true
	cand, err := m.Trust.VerifyEnvelope(e.Candidate, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	for _, raw := range e.Receipts {
		var r pqcrypto.EnvelopeReceipt
		if _, err := canonical.Decode(raw, &r); err != nil {
			return err
		}
		if r.EnvelopeID == cand.EnvelopeID {
			continue
		}
		for i := range a.Chains {
			if v, err := m.Trust.VerifyEnvelope(a.Chains[i].Envelope, pqcrypto.EnvelopeContext{}); err == nil && v.EnvelopeID == r.EnvelopeID {
				a.Chains[i].Receipts = append(a.Chains[i].Receipts, raw)
			}
		}
	}
	a.Chains = append(a.Chains, ChainCopy{Envelope: e.Candidate, Receipts: e.Receipts[len(e.Receipts)-1:]})
	if err := m.J.Save(a); err != nil {
		return err
	}
	m.report(ctx, a, "")
	return nil
}

// recoverEnrollment resumes a journaled enrollment after a restart: without accept_ack it
// fails; with it and no verification started it verifies once; a verification started
// without a result fails with no second bind; undelivered receipts are re-sent.
func (m *Machine) recoverEnrollment(ctx context.Context, a *Account) error {
	e := a.Enrollment
	switch {
	case e == nil || e.Sent:
		return nil
	case len(e.Receipts) > 0:
		return m.enrollSend(ctx, a)
	case !e.AcceptAck:
		return m.enrollFail(ctx, a)
	case !e.VerifyStarted:
		return m.verifyEnrollment(ctx, a)
	}
	return m.enrollFail(ctx, a)
}
