package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Lease and transaction refusals.
var (
	ErrLeaseOpen   = errors.New("broker: a checkout lease is open for this account")
	ErrNoChallenge = errors.New("broker: no challenge is outstanding for this request")
	ErrMinAge      = errors.New("broker: the target's minimum password age has not passed")
)

// ReasonLeaseExpired is the result of a checkout whose lease expired before its wrap was
// delivered.
const ReasonLeaseExpired = "lease_expired"

// CleanupRetry is the pace of a refused lease cleanup (§4.4).
const CleanupRetry = time.Hour

// currentEnvelope is the account's current envelope as VerifyTx needs it.
func (m *Machine) currentEnvelope(a *Account) (*pqcrypto.Chain, *pqcrypto.CurrentEnvelope, error) {
	chains, err := m.chains(a)
	if err != nil {
		return nil, nil, err
	}
	cur := pqcrypto.CurrentEnvelopeOf(chains)
	if cur == nil {
		return nil, nil, nil
	}
	return cur, &pqcrypto.CurrentEnvelope{EnvelopeID: cur.Envelope.EnvelopeID, SecretVersion: cur.Envelope.SecretVersion, ReceiptHead: cur.Head}, nil
}

// verifyTx runs §3.4 against the broker's journal state.
func (m *Machine) verifyTx(a *Account, raw []byte) (*pqcrypto.AccessTransaction, pqcrypto.Digest, *pqcrypto.Chain, error) {
	chain, cur, err := m.currentEnvelope(a)
	if err != nil {
		return nil, pqcrypto.Digest{}, nil, err
	}
	tx, d, err := m.Trust.VerifyTx(raw, pqcrypto.TxContext{BrokerID: m.ID, Now: m.now(), Seen: m.J.Burned, Current: cur, HighestVersion: a.HighestVersion})
	return tx, d, chain, err
}

func accountOf(raw []byte) (pqcrypto.UUID, error) {
	var head struct {
		Scope pqcrypto.Scope `json:"scope"`
	}
	if err := json.Unmarshal(raw, &head); err != nil || !head.Scope.ID.Valid() {
		return "", pqcrypto.ErrHeader
	}
	return head.Scope.ID, nil
}

// Tx takes a relayed vault_checkout or manual_rotation (§3.4, §3.6).
func (m *Machine) Tx(ctx context.Context, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.doTx(ctx, raw)
	m.outcome(ctx, requestIDOf(raw), err)
	return err
}

func (m *Machine) doTx(ctx context.Context, raw []byte) error {
	id, err := accountOf(raw)
	if err != nil {
		return err
	}
	a, err := m.J.Account(id)
	if err != nil {
		return err
	}
	tx, _, chain, err := m.verifyTx(a, raw)
	if err != nil {
		return err
	}
	switch tx.Action.ActionType {
	case pqcrypto.ActionVaultCheckout:
		if err := m.sealedForTarget(ctx, a, chain); err != nil {
			return err
		}
		return m.checkout(ctx, a, tx, raw)
	case pqcrypto.ActionManualRotation:
		return m.manualRotation(ctx, a, tx)
	}
	return pqcrypto.ErrAction
}

// blocked is the §4.2 blocking rule plus open leases, enrollments and quarantine.
func blocked(a *Account) error {
	switch {
	case a.Quarantined:
		return ErrQuarantined
	case a.Run.Open() || a.Enrollment.Open():
		return ErrBlocked
	case a.Lease.Open():
		return ErrLeaseOpen
	}
	return nil
}

// checkout sends a single-use challenge (§3.6 step 2). Nothing else is persisted until the
// possession proof verifies.
func (m *Machine) checkout(ctx context.Context, a *Account, tx *pqcrypto.AccessTransaction, raw []byte) error {
	if err := m.unflushed(ctx, a); err != nil {
		return err
	}
	if err := blocked(a); err != nil {
		return err
	}
	return m.challenge(ctx, a, tx.RequestID, pqcrypto.PurposeDeliver, raw, tx.ExpiresAt.Time)
}

func (m *Machine) challenge(ctx context.Context, a *Account, id pqcrypto.UUID, purpose string, raw []byte, until time.Time) error {
	c := make([]byte, pqcrypto.ChallengeBytes)
	if _, err := rand.Read(c); err != nil {
		return err
	}
	if err := m.J.PutChallenge(id, &Challenge{Purpose: purpose, Challenge: c, Account: a.ID, Tx: raw, ExpiresAt: until}); err != nil {
		return err
	}
	return m.CP.Challenge(ctx, brokerproto.ChallengeRequest{RequestID: id, Challenge: c, Purpose: purpose})
}

// Checkin issues a check-in challenge to the lease holder. Like Proof, it publishes no
// refusal of its own: anyone with a session can send one, so it must not replace a
// request's result (security review and PR Reviewer Guide "Overwritten outcome" on #16).
func (m *Machine) Checkin(ctx context.Context, id pqcrypto.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.doCheckin(ctx, id)
}

func (m *Machine) doCheckin(ctx context.Context, id pqcrypto.UUID) error {
	a, err := m.leaseAccount(id)
	if err != nil {
		return err
	}
	if a.Lease.State != LeaseActive {
		return ErrNoChallenge
	}
	return m.challenge(ctx, a, id, pqcrypto.PurposeCheckin, a.Lease.Tx, m.now().Add(pqcrypto.MaxTxLifetime))
}

func (m *Machine) leaseAccount(id pqcrypto.UUID) (*Account, error) {
	c := m.J.GetChallenge(id)
	var acct pqcrypto.UUID
	if c != nil {
		acct = c.Account
	} else {
		accts, err := m.J.Accounts()
		if err != nil {
			return nil, err
		}
		for _, a := range accts {
			if a.Lease != nil && a.Lease.RequestID == id {
				acct = a.ID
			}
		}
	}
	if acct == "" {
		return nil, ErrNoChallenge
	}
	a, err := m.J.Account(acct)
	if err != nil {
		return nil, err
	}
	if a.Lease == nil || a.Lease.RequestID != id {
		return nil, ErrNoChallenge
	}
	return a, nil
}

// Proof takes a possession proof for an outstanding challenge. A proof that fails persists
// nothing and opens nothing (§3.6 step 2).
func (m *Machine) Proof(ctx context.Context, id pqcrypto.UUID, raw []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.doProof(ctx, id, raw)
}

func (m *Machine) doProof(ctx context.Context, id pqcrypto.UUID, raw []byte) error {
	c := m.J.GetChallenge(id)
	if c == nil || !m.now().Before(c.ExpiresAt) {
		return ErrNoChallenge
	}
	a, err := m.J.Account(c.Account)
	if err != nil {
		return err
	}
	switch c.Purpose {
	case pqcrypto.PurposeDeliver:
		return m.deliver(ctx, a, c, raw)
	case pqcrypto.PurposeCheckin:
		return m.checkinProof(ctx, a, c, raw)
	}
	return ErrNoChallenge
}

// deliverable checks that a proven checkout may open its lease now.
func (m *Machine) deliverable(ctx context.Context, a *Account, chain *pqcrypto.Chain) error {
	if err := m.unflushed(ctx, a); err != nil {
		return err
	}
	if err := blocked(a); err != nil {
		return err
	}
	return m.sealedForTarget(ctx, a, chain)
}

// deliver opens the lease, then verifies the credential once at the pinned target and wraps
// the DEK to the requester's enc_key_id (§3.6 steps 3–4).
func (m *Machine) deliver(ctx context.Context, a *Account, c *Challenge, raw []byte) error {
	// Re-check expiry, the current policy and envelope, then the proof.
	tx, d, chain, err := m.verifyTx(a, c.Tx)
	if err != nil {
		return err
	}
	if _, err := pqcrypto.VerifyPoP(raw, tx, d, c.Challenge, pqcrypto.PurposeDeliver); err != nil {
		return err // unauthenticated: published nowhere, the request's result stands
	}
	// The requester proved possession: its refusals from here on are its outcome.
	if err := m.deliverable(ctx, a, chain); err != nil {
		m.outcome(ctx, tx.RequestID, err)
		return err
	}
	now := m.now()
	a.Lease = &Lease{RequestID: tx.RequestID, Tx: c.Tx, TxDigest: d.Hex(), SecretVersion: tx.Action.SecretVersion, EncKeyID: tx.Action.EncKeyID,
		PolicyDigest: tx.PolicyDigest, TargetDescriptorDigest: tx.Action.TargetDescriptorDigest,
		OpenedAt: now, ExpiresAt: now.Add(time.Duration(tx.Action.CheckoutTTLSeconds) * time.Second), State: LeaseActive, Delivering: true}
	if err := m.J.SaveConsume(a, tx.RequestID, tx.ExpiresAt.Time); err != nil {
		return err
	}
	if err := m.hook("lease_open"); err != nil {
		return err
	}
	// The Control Plane must hold the lease, under the policy it opened under, before the
	// credential is touched: it then refuses a descriptor change until the lease closes.
	if err := m.mirror(ctx, a); err != nil {
		return m.endDelivery(ctx, a, "not_mirrored", false)
	}

	rc, err := m.target(a)
	if err != nil {
		return m.endDelivery(ctx, a, "no_target", false)
	}
	dek, err := chain.Envelope.OpenDEK(pqcrypto.RecipientBroker, string(m.ID), m.Keys.Enc)
	if err != nil {
		return m.endDelivery(ctx, a, "not_openable", false)
	}
	defer clear(dek)
	pw, err := chain.Envelope.OpenPassword(dek)
	if err != nil {
		return m.endDelivery(ctx, a, "not_openable", false)
	}
	s, err := rc.conn.Login(ctx, rc.target, pw)
	clear(pw)
	if errors.Is(err, ErrAuthFailed) {
		return m.endDelivery(ctx, a, HealthAuthFailed, true) // §4.6: deliver nothing, quarantine
	}
	if err != nil {
		return m.endDelivery(ctx, a, "target_unavailable", false)
	}
	s.Close()
	ke := m.Trust.Enrollment(tx.RequesterPrincipalID)
	key := ke.ActiveEncKey(tx.Action.EncKeyID)
	if key == nil {
		return m.endDelivery(ctx, a, string(pqcrypto.ErrNotAllowed), false)
	}
	wrap, err := chain.Envelope.WrapTo(dek, tx.RequesterPrincipalID, key.EncPub)
	if err != nil {
		return err
	}
	a.Lease.Delivery, a.Lease.Delivering = &wrap, false // journaled, so a lost delivery is re-sent (flush)
	if err := m.J.Save(a); err != nil {
		return err
	}
	// Pending, not refused: the lease is active and flush re-sends the wrap (Guide on #16,
	// "Premature refusal").
	if err := m.deliverWrap(ctx, a); err != nil {
		log.Printf("[BROKER] delivery for lease %s not sent: %v", a.Lease.RequestID, err)
	}
	return nil
}

// Refused journals a transaction's refusal, or with an empty code drops it, and sends every
// journaled refusal; Tick and Recover re-send them until acknowledged (Guide on #16, "Lost
// refusals").
func (m *Machine) Refused(ctx context.Context, id pqcrypto.UUID, code string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refuse(ctx, id, code)
}

// outcome records how a relayed message for id ended, with m.mu still held from its
// processing, so outcomes reach the mailbox in the order they happened: an older refusal
// never overwrites a newer success (PR Reviewer Guide "Stale refusal" on #16).
func (m *Machine) outcome(ctx context.Context, id pqcrypto.UUID, err error) {
	if !id.Valid() {
		return
	}
	code := ""
	if errors.Is(err, pqcrypto.ErrReplay) {
		// A duplicate of a request already taken: its earlier outcome stands (PR Reviewer
		// Guide "Overwritten success" on #16).
		log.Printf("[BROKER] request %s replayed: %v", id, err)
		return
	}
	if err != nil {
		log.Printf("[BROKER] request %s refused: %v", id, err)
		code = err.Error()
		var perr pqcrypto.Error
		if errors.As(err, &perr) {
			code = string(perr)
		}
	}
	m.refuse(ctx, id, code) // an accepted message supersedes an earlier refusal
}

func (m *Machine) refuse(ctx context.Context, id pqcrypto.UUID, code string) {
	if code == "" {
		if err := m.J.DeleteRefusal(id); err != nil {
			log.Printf("[BROKER] refusal of %s not dropped: %v", id, err)
		}
		return
	}
	if err := m.J.PutRefusal(id, code); err != nil {
		log.Printf("[BROKER] refusal of %s not journaled: %v", id, err)
		if err := m.CP.TxResult(ctx, brokerproto.TxResultRequest{RequestID: id, Result: code}); err != nil {
			log.Printf("[BROKER] result for %s not delivered: %v", id, err)
		}
	}
	m.refusals(ctx)
}

// requestIDOf is a relayed transaction's request_id, or "" when it has none.
func requestIDOf(raw []byte) pqcrypto.UUID {
	var tx struct {
		RequestID pqcrypto.UUID `json:"request_id"`
	}
	json.Unmarshal(raw, &tx)
	return tx.RequestID
}

// refusals sends the journaled refusals. One the Control Plane rejects is dropped: it would
// reject it again.
func (m *Machine) refusals(ctx context.Context) {
	rs, err := m.J.Refusals()
	if err != nil {
		log.Printf("[BROKER] refusals not read: %v", err)
		return
	}
	for _, x := range rs {
		err := m.CP.TxResult(ctx, brokerproto.TxResultRequest{RequestID: x.RequestID, Result: x.Result})
		var rerr brokerproto.RemoteError
		if err != nil && !errors.As(err, &rerr) {
			log.Printf("[BROKER] result for %s not delivered: %v", x.RequestID, err)
			return
		}
		if err != nil {
			log.Printf("[BROKER] result for %s rejected: %v", x.RequestID, err)
		}
		if err := m.J.DeleteRefusal(x.RequestID); err != nil {
			log.Printf("[BROKER] refusal of %s not dropped: %v", x.RequestID, err)
		}
	}
}

// deliverWrap sends a journaled checkout wrap until the Control Plane acknowledges it.
func (m *Machine) deliverWrap(ctx context.Context, a *Account) error {
	l := a.Lease
	if l == nil || l.Delivery == nil {
		return nil
	}
	if l.State != LeaseActive {
		// Expired before the wrap was delivered (a check-in clears it first): the requester
		// is told, journaled with the drop (PR Reviewer Guide "Missing outcome" on #16).
		l.Delivery = nil
		a.Results = append(a.Results, TxResult{RequestID: l.RequestID, Result: ReasonLeaseExpired})
		if err := m.J.Save(a); err != nil {
			return err
		}
		m.results(ctx, a)
		return nil
	}
	if err := m.CP.Delivery(ctx, brokerproto.DeliveryRequest{RequestID: l.RequestID, Wrap: *l.Delivery}); err != nil {
		return err
	}
	l.Delivery = nil
	return m.J.Save(a)
}

// flush re-sends what the Control Plane has not acknowledged for the account's lease: its
// state and its delivery. Recover and every scheduler tick call it.
func (m *Machine) flush(ctx context.Context, a *Account) {
	// A lease opened whose wrap was never journaled delivered nothing: close it and tell
	// the requester (Guide on #16, "Interrupted delivery").
	if l := a.Lease; l != nil && l.State == LeaseActive && l.Delivering {
		if err := m.endDelivery(ctx, a, "interrupted", false); err != nil {
			log.Printf("[BROKER] interrupted lease %s not closed: %v", l.RequestID, err)
		}
		return
	}
	m.results(ctx, a)
	if err := m.mirror(ctx, a); err != nil {
		return
	}
	if err := m.deliverWrap(ctx, a); err != nil {
		log.Printf("[BROKER] delivery for lease %s not sent: %v", a.Lease.RequestID, err)
	}
}

// unflushed refuses to replace a lease whose last state the Control Plane has not
// acknowledged, after one more attempt to send it: the closure would be lost.
func (m *Machine) unflushed(ctx context.Context, a *Account) error {
	if a.Lease == nil || a.Lease.Mirrored {
		return nil
	}
	if err := m.mirror(ctx, a); err != nil {
		return ErrLeaseOpen
	}
	return nil
}

// endDelivery closes a lease that delivered nothing and, after a denied login, quarantines.
func (m *Machine) endDelivery(ctx context.Context, a *Account, reason string, quarantine bool) error {
	a.Lease.State, a.Lease.CloseReason, a.Lease.Mirrored, a.Lease.Delivery, a.Lease.Delivering = LeaseClosed, reason, false, nil, false
	// Journaled with the closure and re-sent until acknowledged (Guide on #16, "Lost outcome").
	a.Results = append(a.Results, TxResult{RequestID: a.Lease.RequestID, Result: reason})
	if quarantine {
		log.Printf("[BROKER] ALERT: account %s quarantined: the current credential was denied at checkout", a.ID)
		a.Quarantined = true
		setHealth(a, HealthAuthFailed, "checkout verification with the current credential was denied")
	}
	if err := m.J.Save(a); err != nil {
		return err
	}
	_ = m.mirror(ctx, a)
	m.report(ctx, a, "")
	if err := m.applyDeferred(a); err != nil {
		return err
	}
	if b, err := m.J.Account(a.ID); err == nil { // applyDeferred may have saved a newer record
		m.results(ctx, b)
	}
	return nil
}

// checkinProof moves the lease to rotation_pending on a proof from the transaction's cnf
// key (§3.6 step 5).
func (m *Machine) checkinProof(ctx context.Context, a *Account, c *Challenge, raw []byte) error {
	if a.Lease == nil || a.Lease.State != LeaseActive {
		return ErrNoChallenge
	}
	var tx pqcrypto.AccessTransaction
	if _, err := canonical.Decode(a.Lease.Tx, &tx); err != nil {
		return err
	}
	d, err := pqcrypto.ObjDigest(&tx)
	if err != nil || d.Hex() != a.Lease.TxDigest {
		return pqcrypto.ErrStale
	}
	if _, err := pqcrypto.VerifyPoP(raw, &tx, d, c.Challenge, pqcrypto.PurposeCheckin); err != nil {
		return err
	}
	a.Lease.State, a.Lease.NextAttemptAt, a.Lease.Mirrored, a.Lease.Delivery = LeaseRotationPending, m.now(), false, nil
	// "ok" replaces an earlier refusal the mailbox may hold (PR Reviewer Guide "Stale
	// refusal" on #16); it is journaled with the state and re-sent until acknowledged.
	a.Results = append(a.Results, TxResult{RequestID: a.Lease.RequestID, Result: "ok"})
	if err := m.J.SaveConsume(a, a.Lease.RequestID, time.Time{}); err != nil {
		return err
	}
	_ = m.mirror(ctx, a)
	m.results(ctx, a)
	return nil
}

// mirror sends the lease state to checkout_leases; flush re-sends it until acknowledged.
func (m *Machine) mirror(ctx context.Context, a *Account) error {
	l := a.Lease
	if l == nil || l.Mirrored {
		return nil
	}
	err := m.CP.Lease(ctx, brokerproto.LeaseRequest{RequestID: l.RequestID, AccountID: a.ID, SecretVersion: l.SecretVersion, State: l.State,
		CloseReason: l.CloseReason, OpenedAt: pqcrypto.NewTime(l.OpenedAt), ExpiresAt: pqcrypto.NewTime(l.ExpiresAt),
		PolicyDigest: l.PolicyDigest, TargetDescriptorDigest: l.TargetDescriptorDigest})
	if err != nil {
		log.Printf("[BROKER] lease %s not mirrored: %v", l.RequestID, err)
		return err
	}
	l.Mirrored = true
	return m.J.Save(a)
}

// manualRotation runs a rotation now under its own request (§3.4): refused with any rotation
// open or an active lease; with an idle rotation_pending lease it re-arms that lease's
// cleanup instead. It resets the refusal counter but still waits for the minimum age.
func (m *Machine) manualRotation(ctx context.Context, a *Account, tx *pqcrypto.AccessTransaction) error {
	if a.Quarantined {
		return ErrQuarantined
	}
	if a.Run.Open() || a.Enrollment.Open() {
		return ErrBlocked
	}
	now := m.now()
	next := now
	if a.MinAgeDeadline.After(next) {
		next = a.MinAgeDeadline
	}
	if a.Lease.Open() {
		if a.Lease.State != LeaseRotationPending {
			return ErrLeaseOpen
		}
		a.Lease.NextAttemptAt = next
		a.Results = append(a.Results, TxResult{RequestID: tx.RequestID, Result: "ok"}) // re-armed
		if err := m.J.SaveBurn(a, tx.RequestID, tx.ExpiresAt.Time); err != nil {
			return err
		}
		m.results(ctx, a)
		return nil
	}
	a.Refusals = 0
	if next.After(now) {
		a.NextAttemptAt = next
		if err := m.J.SaveBurn(a, tx.RequestID, tx.ExpiresAt.Time); err != nil {
			return err
		}
		return ErrMinAge
	}
	rc, err := m.rotationContext(a)
	if err != nil {
		return err
	}
	op, err := pqcrypto.RequestOpID(tx.RequestID, 0)
	if err != nil {
		return err
	}
	if err := m.start(ctx, a, rc, runSpec{op: op, due: now, burn: tx}); err != nil {
		return err
	}
	m.results(ctx, a)
	return nil
}

// results tells the CLI how its manual_rotation ended, "ok" once released or else the
// state the run stopped in, and re-sends every queued result until the Control Plane
// acknowledges it; Tick and Recover call it through flush (Guide on #16, "Lost results").
func (m *Machine) results(ctx context.Context, a *Account) {
	r := a.Run
	changed := false
	if r != nil && r.Request.Valid() && !r.ResultQueued && (r.Sent && !r.Open() || r.State == StateWriteOutcomeUnknown) {
		res := r.State
		if res == StateReleaseAuthorized {
			res = "ok"
		}
		a.Results, r.ResultQueued, changed = append(a.Results, TxResult{RequestID: r.Request, Result: res}), true, true
	}
	for len(a.Results) > 0 {
		x := a.Results[0]
		if err := m.CP.TxResult(ctx, brokerproto.TxResultRequest{RequestID: x.RequestID, Result: x.Result}); err != nil {
			log.Printf("[BROKER] result for %s not delivered: %v", x.RequestID, err)
			break
		}
		a.Results, changed = a.Results[1:], true
	}
	if changed {
		if err := m.J.Save(a); err != nil {
			log.Printf("[BROKER] results of %s not journaled: %v", a.ID, err)
		}
	}
}

// cleanup runs the next attempt of a rotation_pending lease's cleanup rotation (§3.6 step 5),
// with m.mu held.
func (m *Machine) cleanup(ctx context.Context, a *Account) error {
	l := a.Lease
	if l == nil || l.State != LeaseRotationPending || a.Run.Open() || a.Quarantined || m.now().Before(l.NextAttemptAt) {
		return nil
	}
	rc, err := m.rotationContext(a)
	if err != nil {
		return err
	}
	// Cleanup is bound to the descriptor the lease opened under (§3.3); a change waits in
	// DeferredPolicy, so this holds unless the journal is inconsistent.
	if rc.policy.TargetDescriptorDigest != l.TargetDescriptorDigest {
		m.alert("lease %s cleanup refused: the current policy pins another target", l.RequestID)
		return ErrNeedsEnrollment
	}
	op, err := pqcrypto.RequestOpID(l.RequestID, l.Attempt)
	if err != nil {
		return err
	}
	return m.start(ctx, a, rc, runSpec{op: op, due: m.now(), lease: l.RequestID, attempt: l.Attempt})
}

// leaseAttemptEnded advances a cleanup lease after an attempt that did not release: a
// refusal waits max(min-age deadline, now + 1 h) and never stops; anything else retries.
func (m *Machine) leaseAttemptEnded(a *Account, refused bool) {
	l := a.Lease
	if l == nil || a.Run == nil || l.RequestID != a.Run.Lease {
		return
	}
	l.Attempt++
	l.NextAttemptAt = m.now()
	if refused {
		next := m.now().Add(CleanupRetry)
		if a.MinAgeDeadline.After(next) {
			next = a.MinAgeDeadline
		}
		l.NextAttemptAt = next
		log.Printf("[BROKER] ALERT: account %s: lease cleanup refused; the checked-out credential stays live until %s", a.ID, next.Format(time.RFC3339))
	}
}

// sealedForTarget refuses a checkout whose current envelope was sealed under a policy that
// pins another descriptor: that credential never goes to the new target (§3.3).
func (m *Machine) sealedForTarget(ctx context.Context, a *Account, chain *pqcrypto.Chain) error {
	p, _ := m.Trust.Policy(a.ID)
	if chain == nil || p == nil {
		return ErrNoCurrent
	}
	if chain.Envelope.Policy.TargetDescriptorDigest == p.TargetDescriptorDigest {
		return nil
	}
	if a.Health != HealthNeedsEnrollment {
		setHealth(a, HealthNeedsEnrollment, "the target descriptor changed")
		if err := m.J.Save(a); err != nil {
			return err
		}
		m.report(ctx, a, "")
	}
	return ErrNeedsEnrollment
}
