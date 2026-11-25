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
	p, _ := tr.Policy(id)
	if a.PoolID != b.PoolID || p == nil || p.AccountKind != pqcrypto.KindManaged || p.PoolID != pqcrypto.UUID(b.PoolID) {
		return nil, nil, errNotInPool
	}
	return a, p, nil
}

func (l *Listener) sync(ctx context.Context, tr *pqcrypto.Trust, b *store.Broker, body json.RawMessage) (*SyncReply, error) {
	var req SyncRequest
	if err := decode(body, &req); err != nil {
		return nil, err
	}
	ms, err := l.Store.Guard().Manifests(ctx, int64(max(req.ManifestsAfter, 0)))
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
	accts, err := l.Store.Vault().PoolAccounts(ctx, b.PoolID)
	if err != nil {
		return nil, err
	}
	out.Done = true
	for _, a := range accts {
		if req.AccountsAfter != "" && a.ID <= string(req.AccountsAfter) {
			continue
		}
		if _, _, err := l.account(ctx, tr, b, pqcrypto.UUID(a.ID)); err != nil {
			continue
		}
		if len(out.Accounts) == SyncAccountsPage {
			out.Done = false
			break
		}
		out.Accounts = append(out.Accounts, pqcrypto.UUID(a.ID))
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
	if raw, err := l.Store.Vault().TargetDescriptor(ctx, string(p.TargetDescriptorDigest)); err == nil {
		st.Descriptor = raw
	}
	chains, err := l.Store.Vault().Chains(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	budget, newer := SyncBudget, 0
	for _, c := range chains { // ascending secret_version
		old := c.Envelope.SecretVersion <= uint64(req.AfterVersion)
		if old && (req.Continue || (c.Envelope.EnvelopeID != a.CurrentEnvelopeID && terminated(c))) {
			continue
		}
		cs := ChainState{Envelope: c.Envelope.Envelope, Receipts: []pqcrypto.B64{}}
		size := encoded(c.Envelope.Envelope)
		for _, r := range c.Receipts {
			cs.Receipts = append(cs.Receipts, r.Receipt)
			size += encoded(r.Receipt)
		}
		if !old && size > budget && newer > 0 {
			st.More = true
			break
		}
		budget -= size
		if !old {
			newer++ // a page with More always carries at least one newer chain
		}
		st.Chains = append(st.Chains, cs)
	}
	return st, nil
}

// terminated reports a chain that can take no new receipt but rewrap_user after release.
func terminated(c *store.StoredChain) bool {
	for _, r := range c.Receipts {
		switch r.ReceiptType {
		case pqcrypto.ReceiptAbort, pqcrypto.ReceiptRelease, pqcrypto.ReceiptVaultCommit:
			return true
		}
	}
	return false
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
	stored, err := l.Store.Vault().Chains(ctx, string(req.AccountID))
	if err != nil {
		return err
	}
	chains := map[pqcrypto.UUID]*pqcrypto.Chain{}
	var out []*store.StoredReceipt
	current, runState, release := "", "", false
	for _, raw := range req.Receipts {
		var peek struct {
			EnvelopeID pqcrypto.UUID    `json:"envelope_id"`
			Seq        pqcrypto.Counter `json:"receipt_seq"`
		}
		if json.Unmarshal(raw, &peek) != nil {
			return errors.New("malformed receipt")
		}
		ch := chains[peek.EnvelopeID]
		var sc *store.StoredChain
		for _, c := range stored {
			if c.Envelope.EnvelopeID == string(peek.EnvelopeID) {
				sc = c
			}
		}
		if sc == nil {
			return errors.New("receipt for an unknown envelope")
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
		switch r.ReceiptType {
		case pqcrypto.ReceiptCommitTarget:
			runState = "target_verified"
		case pqcrypto.ReceiptRelease:
			current, runState, release = string(r.EnvelopeID), "release_authorized", true
		case pqcrypto.ReceiptAbort:
			runState, release = "aborted", true
		}
	}
	return l.Store.Vault().Complete(ctx, string(req.OperationID), string(req.AccountID), out, current, runState, release)
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
		return l.Store.Vault().Complete(ctx, string(req.OperationID), string(req.AccountID), nil, "", req.RunState, false)
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
