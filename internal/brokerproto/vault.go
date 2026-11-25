package brokerproto

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Refusals the Control Plane returns on the channel.
var (
	errNotActive   = errors.New("broker is not the active member of its pool")
	errNotInPool   = errors.New("account is not in this broker's pool")
	errNotSigner   = errors.New("object is not signed by this broker")
	errOperation   = errors.New("receipt names another operation")
	errUnsupported = errors.New("unsupported request")
)

// handle answers one broker request. Every request is re-authorized against the current
// manifests, so a broker revoked mid-connection is refused from its next request on.
func (l *Listener) handle(ctx context.Context, b *store.Broker, m Message) (any, error) {
	var out any
	err := l.Trust.View(ctx, func(tr *pqcrypto.Trust) error {
		pool := tr.Pool(pqcrypto.UUID(b.PoolID))
		if pool == nil || pool.Active() == nil || pool.Active().BrokerID != pqcrypto.UUID(b.ID) {
			return errNotActive
		}
		var err error
		switch m.Type {
		case MsgSync:
			out, err = l.sync(ctx, tr, b, m.Body)
		case MsgSyncAccount:
			out, err = l.syncAccount(ctx, tr, b, m.Body)
		case MsgReserve:
			out, err = l.reserve(ctx, tr, b, m.Body)
		case MsgEnvelope:
			err = l.envelope(ctx, tr, b, m.Body)
		case MsgIntent:
			err = l.intent(ctx, tr, b, m.Body)
		case MsgReceipts:
			err = l.receipts(ctx, tr, b, m.Body)
		case MsgStatus:
			err = l.status(ctx, tr, b, m.Body)
		case MsgAccept:
			err = l.accept(ctx, tr, b, m.Body)
		default:
			err = errUnsupported
		}
		return err
	})
	return out, err
}

// account returns the account if its current policy places it in the broker's pool.
func (l *Listener) account(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, id pqcrypto.UUID) (*store.Account, *pqcrypto.PolicyManifest, error) {
	a, err := l.Store.Vault().GetAccount(ctx, string(id))
	if err != nil {
		return nil, nil, errNotInPool
	}
	p := inPool(tr, b, a)
	if p == nil {
		return nil, nil, errNotInPool
	}
	return a, p, nil
}

// inPool returns a's current managed policy if it places a in the broker's pool.
func inPool(tr *pqcrypto.Trust, b *store.Broker, a *store.Account) *pqcrypto.PolicyManifest {
	p, _ := tr.Policy(pqcrypto.UUID(a.ID))
	if a.PoolID != b.PoolID || p == nil || p.AccountKind != pqcrypto.KindManaged || p.PoolID != pqcrypto.UUID(b.PoolID) {
		return nil
	}
	return p
}

func (l *Listener) sync(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) (*SyncReply, error) {
	var req SyncRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	ms, err := l.Store.Guard().ManifestsPage(ctx, int64(max(req.ManifestsAfter, 0)), SyncPage)
	if err != nil {
		return nil, err
	}
	out := &SyncReply{Manifests: []pqcrypto.B64{}, Accounts: []pqcrypto.UUID{}}
	budget := SyncBudget
	for _, m := range ms {
		// A page always carries one manifest, which fits a frame (cptrust.MaxManifest).
		size := encoded(m.Manifest)
		if len(out.Manifests) == SyncPage || (size > budget && len(out.Manifests) > 0) {
			return out, nil
		}
		budget -= size
		out.Manifests = append(out.Manifests, m.Manifest)
	}
	if len(out.Manifests) > 0 {
		return out, nil // accounts come once every manifest is delivered
	}
	// One page scans at most SyncAccountsPage rows, in ID order, eligible or not, and
	// AccountsNext continues past the ones filtered out (PR Reviewer Guide on #10).
	accts, err := l.Store.Vault().PoolAccounts(ctx, b.PoolID, string(req.AccountsAfter), SyncAccountsPage)
	if err != nil {
		return nil, err
	}
	for _, a := range accts {
		if inPool(tr, b, a) != nil {
			out.Accounts = append(out.Accounts, pqcrypto.UUID(a.ID))
		}
	}
	if len(accts) < SyncAccountsPage {
		out.Done = true
	} else {
		out.AccountsNext = pqcrypto.UUID(accts[len(accts)-1].ID)
	}
	return out, nil
}

func (l *Listener) syncAccount(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) (*AccountState, error) {
	var req SyncAccountRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	a, p, err := l.account(ctx, tr, b, req.AccountID)
	if err != nil {
		return nil, err
	}
	st := &AccountState{AccountID: req.AccountID, HighestVersion: pqcrypto.Counter(a.HighestSecretVersion), Chains: []ChainState{}}
	// The broker cannot use a state without its policy's descriptor, so a failed lookup is
	// an error it retries, not a quiet omission (PR Reviewer Guide on #10).
	raw, err := l.Store.Vault().TargetDescriptor(ctx, string(p.TargetDescriptorDigest))
	if err != nil {
		return nil, err
	}
	st.Descriptor = raw
	// One page is the chains above From, in version order: the open ones up to AfterVersion,
	// then every newer one. At most SyncChains+1 are read and the whole reply, descriptor
	// included, stays within SyncBudget; a page always carries one chain, which fits a frame
	// (store.MaxChain), so every continuation advances.
	from, upTo := uint64(req.From), uint64(req.AfterVersion)
	cs, err := l.Store.Vault().OpenChains(ctx, a.ID, from, upTo, SyncChains+1)
	if err != nil {
		return nil, err
	}
	if n := SyncChains + 1 - len(cs); n > 0 {
		newer, err := l.Store.Vault().ChainsAfter(ctx, a.ID, max(from, upTo), n)
		if err != nil {
			return nil, err
		}
		cs = append(cs, newer...)
	}
	budget := SyncBudget - encoded(st.Descriptor)
	for i, c := range cs {
		if i == SyncChains || (size(c) > budget && i > 0) {
			st.More = true
			break
		}
		budget -= add(st, c)
	}
	return st, nil
}

func size(c *store.StoredChain) int {
	n := encoded(c.Envelope.Envelope)
	for _, r := range c.Receipts {
		n += encoded(r.Receipt)
	}
	return n
}

// add appends c to st and returns its encoded size.
func add(st *AccountState, c *store.StoredChain) int {
	cs := ChainState{Envelope: c.Envelope.Envelope, Receipts: []pqcrypto.B64{}}
	for _, r := range c.Receipts {
		cs.Receipts = append(cs.Receipts, r.Receipt)
	}
	st.Chains = append(st.Chains, cs)
	return size(c)
}

func decode(body json.RawMessage, v any) error {
	if err := json.Unmarshal(body, v); err != nil {
		return errors.New("malformed request")
	}
	return nil
}

func (l *Listener) reserve(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) (*ReserveReply, error) {
	var req ReserveRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	if !req.OperationID.Valid() {
		return nil, errors.New("malformed request")
	}
	if _, _, err := l.account(ctx, tr, b, req.AccountID); err != nil {
		return nil, err
	}
	v, err := l.Store.Vault().Reserve(ctx, string(req.AccountID), string(req.OperationID), uint64(req.Reported))
	if err != nil {
		return nil, err
	}
	return &ReserveReply{SecretVersion: pqcrypto.Counter(v)}, nil
}

func (l *Listener) envelope(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) error {
	var req EnvelopeRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	// Re-sending a stored envelope is a no-op, even after the policy has moved on.
	if have, err := l.Store.Vault().EnvelopeByDigest(ctx, digestOf(req.Envelope)); err == nil && slices.Equal(have, req.Envelope) {
		return nil
	}
	v, err := tr.VerifyEnvelope(req.Envelope, pqcrypto.EnvelopeContext{New: true})
	if err != nil {
		return err
	}
	if !v.RotationEnvelope() || v.Signer != pqcrypto.UUID(b.ID) {
		return errNotSigner
	}
	if _, _, err := l.account(ctx, tr, b, v.Scope.ID); err != nil {
		return err
	}
	canon, err := canonical.Marshal(v.SecretEnvelope)
	if err != nil {
		return err
	}
	return l.Store.Vault().PutEnvelope(ctx, string(req.OperationID), &store.StoredEnvelope{EnvelopeID: string(v.EnvelopeID), AccountID: string(v.Scope.ID),
		SecretVersion: uint64(v.SecretVersion), EnvelopeKind: v.EnvelopeKind, Digest: string(v.Digest.Hex()), Envelope: canon})
}

func (l *Listener) intent(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) error {
	var req IntentRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	var in Intent
	canon, err := canonical.Decode(req.Intent, &in)
	if err != nil {
		return err
	}
	if in.BrokerID != pqcrypto.UUID(b.ID) || !in.OperationID.Valid() || !in.NewEnvelopeID.Valid() {
		return errNotSigner
	}
	if _, _, err := l.account(ctx, tr, b, in.AccountID); err != nil {
		return err
	}
	return l.Store.Vault().RecordIntent(ctx, &store.RotationRun{OperationID: string(in.OperationID), AccountID: string(in.AccountID),
		BrokerID: b.ID, SecretVersion: uint64(in.SecretVersion), Intent: canon})
}

// chainFor verifies an account's stored chain for one envelope as history.
func chainFor(tr *pqcrypto.Trust, c *store.StoredChain) (*pqcrypto.Chain, error) {
	v, err := tr.VerifyEnvelope(c.Envelope.Envelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return nil, err
	}
	ch := pqcrypto.NewChain(v)
	for _, r := range c.Receipts {
		if _, err := tr.Append(ch, r.Receipt, pqcrypto.ReceiptContext{}); err != nil {
			return nil, err
		}
	}
	return ch, nil
}

func (l *Listener) receipts(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) error {
	var req ReceiptsRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	if _, _, err := l.account(ctx, tr, b, req.AccountID); err != nil {
		return err
	}
	stored := map[pqcrypto.UUID]*store.StoredChain{} // only the chains the receipts name
	chains := map[pqcrypto.UUID]*pqcrypto.Chain{}
	var out []*store.StoredReceipt
	current, runState, lock := "", "", store.LockKeep
	var err error
	for _, raw := range req.Receipts {
		var peek struct {
			EnvelopeID pqcrypto.UUID    `json:"envelope_id"`
			Seq        pqcrypto.Counter `json:"receipt_seq"`
		}
		if json.Unmarshal(raw, &peek) != nil {
			return errors.New("malformed receipt")
		}
		ch, sc := chains[peek.EnvelopeID], stored[peek.EnvelopeID]
		if sc == nil {
			if sc, err = l.Store.Vault().Chain(ctx, string(req.AccountID), string(peek.EnvelopeID)); errors.Is(err, store.ErrNotFound) {
				return errors.New("receipt for an unknown envelope")
			} else if err != nil {
				return err
			}
			stored[peek.EnvelopeID] = sc
		}
		if ch == nil {
			if ch, err = chainFor(tr, sc); err != nil {
				return err
			}
			chains[peek.EnvelopeID] = ch
		}
		// A receipt the store already holds byte for byte is a retry (§3.5).
		if i := int(peek.Seq) - 1; i >= 0 && i < len(sc.Receipts) && slices.Equal(sc.Receipts[i].Receipt, raw) {
			continue
		}
		prev := ch.Head
		r, err := tr.Append(ch, raw, pqcrypto.ReceiptContext{New: true})
		if err != nil {
			return err
		}
		if r.OperationID != req.OperationID {
			return errOperation
		}
		canon, err := canonical.Marshal(r)
		if err != nil {
			return err
		}
		out = append(out, &store.StoredReceipt{EnvelopeID: string(r.EnvelopeID), ReceiptSeq: uint64(r.ReceiptSeq), ReceiptType: r.ReceiptType,
			OperationID: string(r.OperationID), Digest: string(ch.Head), PrevReceiptHash: string(prev), Receipt: canon})
		switch {
		case r.ReceiptType == pqcrypto.ReceiptCommitTarget:
			runState = "target_verified"
		case r.ReceiptType == pqcrypto.ReceiptRelease:
			current, runState, lock = string(r.EnvelopeID), "release_authorized", store.LockDelete
		case r.ReceiptType == pqcrypto.ReceiptVaultCommit: // a verified enrollment (§4.5 step 3)
			current, lock = string(r.EnvelopeID), store.LockDelete
		case r.Reason == pqcrypto.ReasonEnrollmentFailed: // §4.5 step 4: give the lock back
			lock = store.LockRestore
		case r.Reason == pqcrypto.ReasonSuperseded:
			// Part of an enrollment commit; its vault_commit decides the lock.
		case r.ReceiptType == pqcrypto.ReceiptAbort:
			runState, lock = "aborted", store.LockDelete
		}
	}
	return l.Store.Vault().Complete(ctx, string(req.OperationID), string(req.AccountID), out, current, runState, lock)
}

func (l *Listener) status(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) error {
	var req StatusRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	if _, _, err := l.account(ctx, tr, b, req.AccountID); err != nil {
		return err
	}
	if err := l.Store.Vault().SetHealth(ctx, string(req.AccountID), req.Health, req.Reason); err != nil {
		return err
	}
	if req.RunState == "write_outcome_unknown" && req.OperationID.Valid() {
		return l.Store.Vault().Complete(ctx, string(req.OperationID), string(req.AccountID), nil, "", req.RunState, store.LockKeep)
	}
	return nil
}

// encoded is the base64url size of b plus JSON framing.
func encoded(b []byte) int { return (len(b)+2)/3*4 + 8 }

// digestOf is D(envelope) of canonical bytes, or "" if they do not decode.
func digestOf(raw []byte) string {
	var e pqcrypto.SecretEnvelope
	if _, err := canonical.Decode(raw, &e); err != nil {
		return ""
	}
	d, err := pqcrypto.ObjDigest(&e)
	if err != nil {
		return ""
	}
	return string(d.Hex())
}

func (l *Listener) accept(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) error {
	var req AcceptRequest
	if err := decode(body, &req); err != nil {
		return err
	}
	if _, _, err := l.account(ctx, tr, b, req.AccountID); err != nil {
		return err
	}
	return l.Store.Vault().AcceptEnrollment(ctx, string(req.AccountID), string(req.OperationID), l.now())
}
