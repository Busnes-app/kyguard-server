package broker

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// AckTimeout bounds the wait for the Control Plane's intent acknowledgement (§4.3 rule 2).
const AckTimeout = 30 * time.Second

// Machine runs rotations for the accounts of this broker's pool (§4.2, §4.3). One operation
// runs at a time.
type Machine struct {
	J          *Journal
	Trust      *pqcrypto.Trust
	Keys       *Keys
	ID         pqcrypto.UUID
	CP         ControlPlane
	Connectors map[string]Connector
	Now        func() time.Time
	AckTimeout time.Duration
	// Hook, in tests, stops the machine at a named point as a crash would: returning an
	// error leaves exactly the journal state written so far.
	Hook func(point string) error
	// Alerts, if set, receives every alert as well as the log.
	Alerts func(msg string)

	mu sync.Mutex
}

func (m *Machine) now() time.Time {
	if m.Now != nil {
		return m.Now().UTC()
	}
	return time.Now().UTC()
}

func (m *Machine) hook(point string) error {
	if m.Hook != nil && m.Hook(point) != nil {
		return ErrStopped
	}
	return nil
}

// Errors that stop a rotation before it starts.
var (
	ErrBlocked         = errors.New("broker: a rotation is open for this account")
	ErrQuarantined     = errors.New("broker: account is quarantined")
	ErrNoCurrent       = errors.New("broker: account has no current envelope this broker can open")
	ErrNotActive       = errors.New("broker: this broker is not the active member of the account's pool")
	ErrStaleVersion    = errors.New("broker: reserved secret_version is not above the highest seen")
	ErrNoDescriptor    = errors.New("broker: no verified target descriptor for the account's policy")
	ErrNeedsEnrollment = errors.New("broker: the current credential was sealed for another target; enroll at the new one")
	errNoAck           = errors.New("broker: no Control Plane acknowledgement of the intent")
	passwordAlphabet   = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!@"
	passwordLength     = 32
	passwordCharGroups = []string{"ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "-_.!@"}
)

// NewPassword returns 32 characters from crypto/rand with at least one uppercase letter,
// lowercase letter, digit and one of -_.!@ (§4.2).
func NewPassword() []byte {
	for {
		p := make([]byte, passwordLength)
		for i := range p {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(len(passwordAlphabet))))
			if err != nil {
				panic(err)
			}
			p[i] = passwordAlphabet[n.Int64()]
		}
		ok := true
		for _, g := range passwordCharGroups {
			ok = ok && strings.ContainsAny(string(p), g)
		}
		if ok {
			return p
		}
		clear(p)
	}
}

// chains verifies the account's journaled chains as history.
func (m *Machine) chains(a *Account) ([]*pqcrypto.Chain, error) {
	var out []*pqcrypto.Chain
	for _, c := range a.Chains {
		v, err := m.Trust.VerifyEnvelope(c.Envelope, pqcrypto.EnvelopeContext{})
		if err != nil {
			return nil, err
		}
		ch := pqcrypto.NewChain(v)
		for _, r := range c.Receipts {
			if _, err := m.Trust.Append(ch, r, pqcrypto.ReceiptContext{}); err != nil {
				return nil, err
			}
		}
		out = append(out, ch)
	}
	return out, nil
}

// context is what a new rotation needs from the verified state.
type rotationContext struct {
	policy  *pqcrypto.PolicyManifest
	digest  pqcrypto.Digest
	target  *pqcrypto.TargetDescriptor
	current *pqcrypto.Chain
	conn    Connector
	// scheduled is set for a scheduled occurrence, which never runs while the target's
	// minimum password age is longer than the schedule interval (§4.4).
	scheduled bool
}

func (m *Machine) rotationContext(a *Account) (*rotationContext, error) {
	p, d := m.Trust.Policy(a.ID)
	if p == nil || p.AccountKind != pqcrypto.KindManaged {
		return nil, ErrNotActive
	}
	pool := m.Trust.Pool(p.PoolID)
	if pool == nil || pool.Active() == nil || pool.Active().BrokerID != m.ID {
		return nil, ErrNotActive
	}
	td, conn, err := m.descriptor(p.TargetDescriptorDigest)
	if err != nil {
		return nil, err
	}
	chains, err := m.chains(a)
	if err != nil {
		return nil, err
	}
	cur := pqcrypto.CurrentEnvelopeOf(chains)
	if cur == nil {
		return nil, ErrNoCurrent
	}
	// A credential sealed for another target is never sent to this one (§3.3).
	if cur.Envelope.Policy.TargetDescriptorDigest != p.TargetDescriptorDigest {
		return nil, ErrNeedsEnrollment
	}
	return &rotationContext{policy: p, digest: d, target: td, current: cur, conn: conn}, nil
}

// descriptor returns a verified descriptor by digest and its connector.
func (m *Machine) descriptor(digest pqcrypto.HexID) (*pqcrypto.TargetDescriptor, Connector, error) {
	raw := m.J.Descriptor(digest)
	if raw == nil {
		return nil, nil, ErrNoDescriptor
	}
	td, dg, err := pqcrypto.DecodeTargetDescriptor(raw)
	if err != nil || dg.Hex() != digest {
		return nil, nil, ErrNoDescriptor
	}
	conn := m.Connectors[td.ConnectorType]
	if conn == nil {
		return nil, nil, fmt.Errorf("broker: no connector for %s", td.ConnectorType)
	}
	return td, conn, nil
}

// open unwraps an envelope sealed to this broker. The caller wipes the result.
func (m *Machine) open(e *pqcrypto.SecretEnvelope) ([]byte, error) {
	dek, err := e.OpenDEK(pqcrypto.RecipientBroker, string(m.ID), m.Keys.Enc)
	if err != nil {
		return nil, ErrNoCurrent
	}
	defer clear(dek)
	return e.OpenPassword(dek)
}

// Rotate starts a new attempt for an occurrence and drives it to its end (§4.2). The
// attempt number continues from an earlier attempt of the same occurrence.
func (m *Machine) Rotate(ctx context.Context, account pqcrypto.UUID, occurrence pqcrypto.Counter, due time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, err := m.J.Account(account)
	if err != nil {
		return err
	}
	return m.rotate(ctx, a, occurrence, due)
}

// rotate is Rotate with m.mu held and the account loaded.
func (m *Machine) rotate(ctx context.Context, a *Account, occurrence pqcrypto.Counter, due time.Time) error {
	account := a.ID
	if a.Quarantined {
		return ErrQuarantined
	}
	if a.Run != nil && a.Run.State == StateReserving {
		if err := m.settle(ctx, a); err != nil {
			return fmt.Errorf("%w: an earlier reservation is not settled: %w", ErrBlocked, err)
		}
	}
	if a.Run.Open() || a.Enrollment.Open() {
		return ErrBlocked
	}
	rc, err := m.rotationContext(a)
	if errors.Is(err, ErrNeedsEnrollment) && a.Health != HealthNeedsEnrollment {
		setHealth(a, HealthNeedsEnrollment, "the target descriptor changed")
		if serr := m.J.Save(a); serr != nil {
			return serr
		}
		m.report(ctx, a, "")
	}
	if err != nil {
		return err
	}
	rc.scheduled = true
	attempt := pqcrypto.Counter(0)
	if r := a.Run; r != nil && r.PolicyEpoch == rc.policy.Epoch && r.Occurrence == occurrence {
		attempt = r.Attempt + 1
	}
	op, err := pqcrypto.RotationOpID(account, rc.policy.Epoch, occurrence, attempt)
	if err != nil {
		return err
	}
	return m.start(ctx, a, rc, op, occurrence, attempt, due)
}

func (m *Machine) start(ctx context.Context, a *Account, rc *rotationContext, op pqcrypto.UUID, occurrence, attempt pqcrypto.Counter, due time.Time) error {
	// A run whose journaled receipts the Control Plane has not acknowledged is delivered
	// before a new run replaces it; otherwise its operation ID and lock would be lost.
	if r := a.Run; r != nil && len(r.Receipts) > 0 && !r.Sent {
		if err := m.send(ctx, a); err != nil {
			return fmt.Errorf("%w: earlier results not delivered: %w", ErrBlocked, err)
		}
	}
	// The attempt is journaled before the reservation, so a crash or a lost reply can
	// never leave a Control Plane lock with no local run to settle it.
	a.Run = &Run{OperationID: op, PolicyEpoch: rc.policy.Epoch, Occurrence: occurrence, Attempt: attempt, Due: due,
		State: StateReserving, SeenBefore: a.HighestVersion, OldEnvelopeID: rc.current.Envelope.EnvelopeID}
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("reserving"); err != nil {
		return err
	}
	pNew := NewPassword()
	defer clear(pNew)
	if err := m.prepare(ctx, a, rc, pNew); err != nil {
		return err
	}
	if err := m.hook("prepared"); err != nil {
		return err
	}
	if err := m.CP.StoreEnvelope(ctx, op, a.Run.NewEnvelope); err != nil {
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	return m.mutate(ctx, a, rc, pNew)
}

// prepare reserves the reserving run's version under its operation ID, seals P_new and
// journals the run prepared. A refusal means the Control Plane holds no reservation for
// the operation, so the run ends with nothing to send; any other failure leaves it
// reserving, to be settled later.
func (m *Machine) prepare(ctx context.Context, a *Account, rc *rotationContext, pNew []byte) error {
	r := a.Run
	version, err := m.CP.Reserve(ctx, a.ID, r.OperationID, a.HighestVersion)
	var refused brokerproto.RemoteError
	if errors.As(err, &refused) {
		r.State, r.Sent = StateAborted, true
		if serr := m.J.Save(a); serr != nil {
			return serr
		}
		return err
	}
	if err != nil {
		return err
	}
	// Sync may already have copied this operation's own reservation into HighestVersion, so
	// the version is checked against what was seen before reserving and every known envelope.
	if version <= r.SeenBefore || slices.ContainsFunc(a.Chains, func(c ChainCopy) bool { return versionOf(c.Envelope) >= version }) {
		log.Printf("[BROKER] ALERT: Control Plane reserved secret_version %s for %s, at or below the highest seen %s", version, a.ID, r.SeenBefore)
		return ErrStaleVersion
	}
	env, err := m.seal(rc, a.ID, version, pNew)
	if err != nil {
		return err
	}
	a.HighestVersion = max(a.HighestVersion, version)
	r.State, r.SecretVersion, r.NewEnvelope = StatePrepared, version, env
	return m.J.Save(a)
}

// settle ends a run journaled before its reservation was known: the same operation's
// reservation is fetched again and, if one exists, its envelope is stored and aborted
// (restart_before_send) so the Control Plane releases the lock. No write was ever sent.
func (m *Machine) settle(ctx context.Context, a *Account) error {
	p, d := m.Trust.Policy(a.ID)
	if p == nil || p.AccountKind != pqcrypto.KindManaged {
		return ErrNotActive
	}
	pw := NewPassword()
	defer clear(pw)
	if err := m.prepare(ctx, a, &rotationContext{policy: p, digest: d}, pw); err != nil {
		if a.Run.State == StateAborted {
			return nil // nothing was reserved
		}
		return err
	}
	return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
}

// versionOf reads an envelope's secret_version, or 0.
func versionOf(raw []byte) pqcrypto.Counter {
	var v struct {
		V pqcrypto.Counter `json:"secret_version"`
	}
	json.Unmarshal(raw, &v)
	return v.V
}

// seal builds and signs the P_new envelope: the active broker, and the recovery key when
// the policy enables escrow (§3.5).
func (m *Machine) seal(rc *rotationContext, account pqcrypto.UUID, version pqcrypto.Counter, password []byte) ([]byte, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	to := []pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(m.ID), Pub: m.Keys.Enc.Public().Bytes()}}
	recoveryEpoch := pqcrypto.Counter(0)
	if rc.policy.RecoveryEscrowEnabled {
		rk := m.Trust.RecoveryKey()
		to = append(to, pqcrypto.SealTo{Type: pqcrypto.RecipientRecovery, ID: string(rk.RecoveryKeyID), Pub: rk.RecoveryPubkey})
		recoveryEpoch = rk.Epoch
	}
	h := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: m.Trust.DeploymentID(), Epoch: rc.policy.Epoch,
		Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: account}, SignerRole: pqcrypto.RoleBroker}
	e, err := pqcrypto.Seal(h, pqcrypto.KindManaged, pqcrypto.UUID(id.String()), version, rc.digest.Hex(), recoveryEpoch, m.now(), password, to)
	if err != nil {
		return nil, err
	}
	if err := pqcrypto.Sign(e, pqcrypto.RoleBroker, m.Keys.Sig); err != nil {
		return nil, err
	}
	raw, err := canonical.Marshal(e)
	if err != nil {
		return nil, err
	}
	if _, err := m.Trust.VerifyEnvelope(raw, pqcrypto.EnvelopeContext{New: true}); err != nil {
		return nil, err
	}
	return raw, nil
}

// mutate logs in with P_old, reads the baseline, then sends the write through the
// intent → acknowledgement → ack_received order of §4.3 rule 2.
func (m *Machine) mutate(ctx context.Context, a *Account, rc *rotationContext, pNew []byte) error {
	pOld, err := m.open(rc.current.Envelope.SecretEnvelope)
	if err != nil {
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	defer clear(pOld)
	s, err := rc.conn.Login(ctx, rc.target, pOld)
	if errors.Is(err, ErrAuthFailed) {
		// §4.6: one attempt only; never retry a credential. The quarantine is journaled with
		// the abort, before any Control Plane call can fail.
		log.Printf("[BROKER] ALERT: account %s quarantined: the current credential was denied", a.ID)
		a.Quarantined = true
		setHealth(a, HealthAuthFailed, "pre-rotation login with the current credential was denied")
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	if err != nil {
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	baseline, err := s.Baseline(ctx)
	if err != nil {
		s.Close()
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	if ar, ok := s.(AgeReporter); ok {
		if last, minAge, err := ar.PasswordAge(ctx); err == nil {
			a.MinAgeSeconds, a.MinAgeDeadline = int64(minAge/time.Second), last.Add(minAge)
		}
	}
	// Recheck the age just read: Tick saw only the journaled one (PR Reviewer Guide on #12).
	if sch := rc.policy.RotationSchedule; rc.scheduled && sch != nil && a.MinAgeSeconds > sch.IntervalSeconds {
		s.Close()
		setHealth(a, HealthRotationFailed, ReasonBelowMinAge)
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	}
	committed := false
	commit := func() error {
		if err := m.commitIntent(ctx, a, rc, baseline); err != nil {
			return err
		}
		committed = true
		return nil
	}
	werr := s.Change(ctx, pOld, pNew, commit)
	s.Close() // the connection that carried the write is closed before the probe (§4.3 rule 5)
	if errors.Is(werr, ErrStopped) {
		return werr
	}
	if err := m.hook("after_write"); err != nil {
		return err
	}
	switch {
	case !committed && errors.Is(werr, ErrRefused):
		return m.abort(ctx, a, pqcrypto.ReasonRefused)
	case !committed:
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend)
	case errors.Is(werr, ErrRefused):
		return m.abort(ctx, a, pqcrypto.ReasonRefused) // deterministic refusal: target unchanged
	case werr != nil:
		a.Run.State = StateWriteOutcomeUnknown
		if err := m.J.Save(a); err != nil {
			return err
		}
		m.report(ctx, a, StateWriteOutcomeUnknown)
	}
	return m.probe(ctx, a, rc, baseline)
}

// commitIntent journals the intent, waits for the Control Plane to hold the same record,
// then journals ack_received. Only after that may the write leave.
func (m *Machine) commitIntent(ctx context.Context, a *Account, rc *rotationContext, baseline string) error {
	env, err := m.Trust.VerifyEnvelope(a.Run.NewEnvelope, pqcrypto.EnvelopeContext{New: true})
	if err != nil {
		return err
	}
	in := brokerproto.Intent{BrokerID: m.ID, OperationID: a.Run.OperationID, AccountID: a.ID, SecretVersion: a.Run.SecretVersion,
		Endpoint: fmt.Sprintf("%s:%d", rc.target.Endpoint.Host, rc.target.Endpoint.Port), Baseline: baseline,
		OldEnvelopeID: a.Run.OldEnvelopeID, NewEnvelopeID: env.EnvelopeID}
	raw, err := canonical.Marshal(&in)
	if err != nil {
		return err
	}
	a.Run.Intent = raw
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("intent"); err != nil {
		return err
	}
	timeout := m.AckTimeout
	if timeout == 0 {
		timeout = AckTimeout
	}
	actx, cancel := context.WithTimeout(ctx, timeout)
	err = m.CP.Intent(actx, raw)
	cancel()
	if err != nil {
		return errNoAck // a late acknowledgement is dropped with the call
	}
	a.Run.AckReceived, a.Run.State = true, StateMutating
	if err := m.J.Save(a); err != nil {
		return err
	}
	return m.hook("ack_received")
}

// probe is the one P_new verification: recorded (fsync) before it is sent; any result but
// success quarantines (§4.3 rule 5).
func (m *Machine) probe(ctx context.Context, a *Account, rc *rotationContext, baseline string) error {
	a.Run.ProbeRecorded = true
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("probe_recorded"); err != nil {
		return err
	}
	env, err := m.Trust.VerifyEnvelope(a.Run.NewEnvelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	pNew, err := m.open(env.SecretEnvelope)
	if err != nil {
		return err
	}
	verr := rc.conn.Verify(ctx, rc.target, pNew, baseline)
	clear(pNew)
	a.Run.ProbeDone = true
	if verr != nil {
		a.Run.State = StateWriteOutcomeUnknown
		return m.quarantine(ctx, a, HealthQuarantined, "the P_new probe did not verify")
	}
	return m.release(ctx, a, env)
}

// release appends commit_target, completes the (empty, 1A) dependencies and appends
// release, then sends both (§4.2). It resumes from whatever the journal already holds, so a
// restart between the two receipts finishes the run instead of stranding it.
func (m *Machine) release(ctx context.Context, a *Account, env *pqcrypto.VerifiedEnvelope) error {
	ch := pqcrypto.NewChain(env)
	for _, r := range a.Run.Receipts {
		if _, err := m.Trust.Append(ch, r, pqcrypto.ReceiptContext{}); err != nil {
			return err
		}
	}
	if !ch.CommitTarget {
		commit, err := m.receipt(ch, a.Run.OperationID, pqcrypto.ReceiptCommitTarget, "")
		if err != nil {
			return err
		}
		a.Run.State, a.Run.Receipts = StateTargetVerified, []pqcrypto.B64{commit}
		if err := m.J.Save(a); err != nil {
			return err
		}
		if err := m.hook("target_verified"); err != nil {
			return err
		}
	}
	if !ch.Released {
		a.Run.State = StateDependenciesComplete // 1A descriptors carry no dependencies
		rel, err := m.receipt(ch, a.Run.OperationID, pqcrypto.ReceiptRelease, "")
		if err != nil {
			return err
		}
		a.Run.Receipts = append(a.Run.Receipts, rel)
		if err := m.J.Save(a); err != nil {
			return err
		}
	}
	return m.send(ctx, a)
}

// abort signs abort at seq 1 of the run's envelope and sends it (§4.2).
func (m *Machine) abort(ctx context.Context, a *Account, reason string) error {
	env, err := m.Trust.VerifyEnvelope(a.Run.NewEnvelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	r, err := m.receipt(pqcrypto.NewChain(env), a.Run.OperationID, pqcrypto.ReceiptAbort, reason)
	if err != nil {
		return err
	}
	a.Run.State, a.Run.Reason, a.Run.Receipts = StateAborted, reason, []pqcrypto.B64{r}
	if reason == pqcrypto.ReasonRefused {
		setHealth(a, HealthRotationFailed, "the target refused the change")
		m.refused(a)
	}
	if err := m.J.Save(a); err != nil {
		return err
	}
	return m.send(ctx, a)
}

// receipt signs the next receipt of ch and appends it to ch.
func (m *Machine) receipt(ch *pqcrypto.Chain, op pqcrypto.UUID, typ, reason string) ([]byte, error) {
	p, _ := m.Trust.Policy(ch.Envelope.Scope.ID)
	r := &pqcrypto.EnvelopeReceipt{Header: pqcrypto.Header{Type: pqcrypto.TypeReceipt, DeploymentID: m.Trust.DeploymentID(), Epoch: p.Epoch,
		Scope: ch.Envelope.Scope, SignerRole: pqcrypto.RoleBroker}, EnvelopeID: ch.Envelope.EnvelopeID, EnvelopeKind: ch.Envelope.EnvelopeKind,
		SecretVersion: ch.Envelope.SecretVersion, ReceiptSeq: ch.Seq + 1, PrevReceiptHash: ch.Head, ReceiptType: typ, Reason: reason,
		OperationID: op, ExtraRecipients: []pqcrypto.Recipient{}, IssuedAt: pqcrypto.NewTime(m.now())}
	return m.signReceipt(ch, r)
}

func (m *Machine) signReceipt(ch *pqcrypto.Chain, r *pqcrypto.EnvelopeReceipt) ([]byte, error) {
	if r.OperationID == "" {
		return nil, errors.New("broker: receipt without operation")
	}
	if err := pqcrypto.Sign(r, pqcrypto.RoleBroker, m.Keys.Sig); err != nil {
		return nil, err
	}
	raw, err := canonical.Marshal(r)
	if err != nil {
		return nil, err
	}
	if _, err := m.Trust.Append(ch, raw, pqcrypto.ReceiptContext{New: true}); err != nil {
		return nil, err
	}
	return raw, nil
}

// send delivers the run's receipts until the Control Plane acknowledges them; a repeat is a
// no-op there (§4.3 rule 7). On acknowledgement the chain joins the broker's copy.
func (m *Machine) send(ctx context.Context, a *Account) error {
	if err := m.hook("before_send"); err != nil {
		return err
	}
	if err := m.CP.StoreEnvelope(ctx, a.Run.OperationID, a.Run.NewEnvelope); err != nil {
		return err
	}
	if err := m.CP.Receipts(ctx, a.Run.OperationID, a.ID, a.Run.Receipts); err != nil {
		return err
	}
	a.Run.Sent = true
	a.Chains = append(a.Chains, ChainCopy{Envelope: a.Run.NewEnvelope, Receipts: a.Run.Receipts})
	if a.Run.State == StateDependenciesComplete {
		a.Run.State = StateReleaseAuthorized
		a.LastConsumedDue, a.CurrentCommitAt = a.Run.Due, m.now()
		setHealth(a, HealthHealthy, "")
		a.Refusals, a.NextAttemptAt = 0, time.Time{}
	}
	if err := m.J.Save(a); err != nil {
		return err
	}
	m.report(ctx, a, "")
	return nil
}

// quarantine stops all work on the account until re-enrollment (§4.3 rule 6).
func (m *Machine) quarantine(ctx context.Context, a *Account, health, reason string) error {
	log.Printf("[BROKER] ALERT: account %s quarantined: %s", a.ID, reason)
	a.Quarantined = true
	setHealth(a, health, reason)
	if err := m.J.Save(a); err != nil {
		return err
	}
	if err := m.hook("quarantined"); err != nil {
		return err
	}
	m.report(ctx, a, "")
	return nil
}

// setHealth changes the account's health and marks it unreported, in the caller's next
// journal save, so a crash before report still leaves it to be sent by Recover.
func setHealth(a *Account, health, reason string) {
	a.Health, a.HealthReason, a.Unreported = health, reason, true
}

// report tells the Control Plane the account's health. Unreported is cleared only once the
// Control Plane acknowledges it; until then every Recover sends the health again.
func (m *Machine) report(ctx context.Context, a *Account, runState string) {
	s := brokerproto.StatusRequest{AccountID: a.ID, Health: a.Health, Reason: a.HealthReason}
	if runState != "" && a.Run != nil {
		s.OperationID, s.RunState = a.Run.OperationID, runState
	}
	err := m.CP.Status(ctx, s)
	if err != nil {
		log.Printf("[BROKER] status for %s not delivered: %v", a.ID, err)
	}
	if unreported := err != nil; unreported != a.Unreported {
		a.Unreported = unreported
		if err := m.J.Save(a); err != nil {
			log.Printf("[BROKER] status flag for %s not journaled: %v", a.ID, err)
		}
	}
}

// Recover settles every journaled run after a restart (§4.3 rule 3) and re-sends results and
// health the Control Plane has not acknowledged; it fails while any health is undelivered. It never sends a second write: an intent
// with ack_received gets only the one probe, and a recorded probe without a result
// quarantines.
func (m *Machine) Recover(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	accts, err := m.J.Accounts()
	if err != nil {
		return err
	}
	var errs []error
	for _, a := range accts {
		if a.Unreported {
			m.report(ctx, a, "")
		}
		if err := m.recover(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", a.ID, err))
		}
		if err := m.recoverEnrollment(ctx, a); err != nil {
			errs = append(errs, fmt.Errorf("account %s enrollment: %w", a.ID, err))
		}
		if b, err := m.J.Account(a.ID); err == nil && b.Unreported { // keeps the start-up retry going until the health is delivered
			errs = append(errs, fmt.Errorf("account %s: health not delivered", a.ID))
		}
	}
	return errors.Join(errs...)
}

func (m *Machine) recover(ctx context.Context, a *Account) error {
	r := a.Run
	switch {
	case r == nil || r.Sent:
		return nil
	case r.State == StateReserving:
		return m.settle(ctx, a)
	case r.State == StateTargetVerified || r.State == StateDependenciesComplete:
		env, err := m.Trust.VerifyEnvelope(r.NewEnvelope, pqcrypto.EnvelopeContext{})
		if err != nil {
			return err
		}
		return m.release(ctx, a, env) // finish the receipts, then send
	case len(r.Receipts) > 0:
		return m.send(ctx, a)
	case r.ProbeDone:
		return nil // quarantined; only re-enrollment ends it
	case r.ProbeRecorded:
		r.State, r.ProbeDone = StateWriteOutcomeUnknown, true
		return m.quarantine(ctx, a, HealthQuarantined, "a P_new probe was recorded and has no result")
	case !r.AckReceived:
		return m.abort(ctx, a, pqcrypto.ReasonRestartBeforeSend) // no write was sent
	}
	// ack_received: the write may have reached the target.
	r.State = StateWriteOutcomeUnknown
	if err := m.J.Save(a); err != nil {
		return err
	}
	m.report(ctx, a, StateWriteOutcomeUnknown)
	if p, _ := m.Trust.Policy(a.ID); p == nil || m.Trust.Pool(p.PoolID) == nil || m.Trust.Pool(p.PoolID).Active() == nil || m.Trust.Pool(p.PoolID).Active().BrokerID != m.ID {
		return m.quarantine(ctx, a, HealthQuarantined, "an intent of a broker that is no longer active")
	}
	// The probe goes to the target the intent was for: the descriptor its envelope's sealing
	// policy pins, whatever the current policy says now.
	env, err := m.Trust.VerifyEnvelope(r.NewEnvelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return err
	}
	td, conn, err := m.descriptor(env.Policy.TargetDescriptorDigest)
	if err != nil {
		return err
	}
	rc := &rotationContext{policy: env.Policy, target: td, conn: conn}
	var in brokerproto.Intent
	if _, err := canonical.Decode(r.Intent, &in); err != nil {
		return err
	}
	return m.probe(ctx, a, rc, in.Baseline)
}
