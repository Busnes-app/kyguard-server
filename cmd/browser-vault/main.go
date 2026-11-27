//go:build js && wasm

// The browser vault runs the same KyGuard signatures and envelope verification
// as the broker. This binary is built only for the browser's dedicated worker.
package main

import (
	"encoding/json"
	"errors"
	"slices"
	"syscall/js"
	"time"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/vaultclient"
	"github.com/google/uuid"
)

type watermark struct {
	Epoch  pqcrypto.Counter `json:"epoch"`
	Digest pqcrypto.HexID   `json:"digest"`
}

type snapshot struct {
	Fingerprint pqcrypto.HexID       `json:"fingerprint"`
	Bundle      pqcrypto.B64         `json:"bundle"`
	Manifests   []pqcrypto.B64       `json:"manifests"`
	Heads       map[string]watermark `json:"heads"`
}

type accountContext struct {
	Account  pqcrypto.UUID  `json:"account"`
	Target   pqcrypto.B64   `json:"target"`
	Envelope pqcrypto.B64   `json:"envelope"`
	Receipts []pqcrypto.B64 `json:"receipts"`
}

type request struct {
	Action      string                      `json:"action"`
	Trust       snapshot                    `json:"trust"`
	Context     *accountContext             `json:"context"`
	User        string                      `json:"user_id"`
	Issuer      string                      `json:"issuer"`
	Subject     string                      `json:"subject"`
	Method      string                      `json:"method"`
	Passphrase  string                      `json:"passphrase"`
	Enrollment  pqcrypto.B64                `json:"enrollment"`
	Sealed      pqcrypto.KeyEnvelope        `json:"sealed"`
	Seed        pqcrypto.B64                `json:"seed"`
	Handoff     *vaultclient.KeyringHandoff `json:"handoff"`
	Reservation pqcrypto.UUID               `json:"reservation,omitzero"`
	Version     pqcrypto.Counter            `json:"version"`
	Password    string                      `json:"password"`
	TTL         int64                       `json:"ttl"`
	Original    pqcrypto.B64                `json:"original"`
	Tx          pqcrypto.B64                `json:"tx"`
	Challenge   pqcrypto.B64                `json:"challenge"`
	Purpose     string                      `json:"purpose"`
	Wrap        *pqcrypto.Recipient         `json:"wrap"`
}

type worker struct {
	trust         *pqcrypto.Trust
	key           *vaultclient.UserKey
	suiteKey      []byte
	suiteUser     string
	handoff       *vaultclient.KeyringHandoff
	account       *accountContext
	current       *pqcrypto.Chain
	checkout      *vaultclient.Checkout
	leaseEnvelope pqcrypto.B64
}

func main() {
	v := &worker{}
	call := js.FuncOf(func(_ js.Value, args []js.Value) any {
		var req request
		if len(args) != 1 || json.Unmarshal([]byte(args[0].String()), &req) != nil {
			return `{"error":"Invalid browser vault request"}`
		}
		out, err := v.handle(req)
		if err != nil {
			raw, _ := json.Marshal(map[string]string{"error": err.Error()})
			return string(raw)
		}
		raw, err := json.Marshal(map[string]any{"value": out})
		if err != nil {
			return `{"error":"Could not encode browser vault response"}`
		}
		return string(raw)
	})
	js.Global().Set("kyGuardVault", call)
	select {}
}

func (v *worker) handle(r request) (any, error) {
	switch r.Action {
	case "keyring-start":
		k, err := xwing.Generate()
		if err != nil {
			return nil, err
		}
		seed := k.Seed()
		defer clear(seed)
		return map[string]string{"seed": pqcrypto.EncodeB64(seed), "keyring_pk": pqcrypto.EncodeB64(k.Public().Bytes())}, nil
	case "keyring-open":
		if r.Handoff == nil || r.User == "" {
			return nil, errors.New("missing KyIdentity handoff")
		}
		defer clear(r.Seed)
		key, err := r.Handoff.Open(r.Seed)
		if err != nil {
			return nil, err
		}
		clear(v.suiteKey)
		v.suiteKey, v.suiteUser, v.handoff = key, r.User, r.Handoff
		return nil, nil
	case "sync":
		return v.sync(r.Trust, r.Context)
	case "lock":
		v.key, v.checkout, v.leaseEnvelope = nil, nil, nil
		return nil, nil
	}
	if v.trust == nil {
		return nil, errors.New("verify the deployment trust before using the vault")
	}
	switch r.Action {
	case "new-key":
		return v.newKey(r)
	case "unlock":
		return nil, v.unlock(r)
	}
	if v.key == nil {
		return nil, errors.New("unlock your KyGuard key first")
	}
	switch r.Action {
	case "proof":
		if v.checkout != nil {
			raw, err := v.checkout.Proof(r.Challenge, r.Purpose)
			return pqcrypto.B64(raw), err
		}
	case "open-delivery":
		if v.checkout != nil && r.Wrap != nil && r.Wrap.RecipientID == string(v.key.Principal) &&
			string(r.Wrap.KeyID) == v.key.Enc.Public().ID() {
			pw, err := vaultclient.OpenDelivery(v.trust, v.leaseEnvelope, *r.Wrap, v.key.Enc)
			if err != nil {
				return nil, err
			}
			defer clear(pw)
			return string(pw), nil
		}
	case "reserve", "enroll", "checkout", "review-approval", "approve", "attach-approval":
		return v.accountAction(r)
	}
	return nil, errors.New("this action has no active vault request")
}

func (v *worker) sync(s snapshot, account *accountContext) (any, error) {
	tr, err := pqcrypto.NewTrust(s.Bundle, s.Fingerprint)
	if err != nil {
		return nil, err
	}
	heads := map[string]watermark{}
	for _, raw := range s.Manifests {
		if _, err := tr.Accept(raw); err != nil {
			return nil, err
		}
	}
	for _, rec := range tr.Records() {
		heads[rec.Type+"/"+string(rec.ScopeID)] = watermark{rec.Epoch, rec.Digest.Hex()}
	}
	for k, previous := range s.Heads {
		now := heads[k]
		if now.Epoch < previous.Epoch || (now.Epoch == previous.Epoch && now.Digest != previous.Digest) {
			return nil, errors.New("KyGuard returned older or conflicting signed trust data")
		}
	}
	out := map[string]any{"heads": heads}
	var chain *pqcrypto.Chain
	if account != nil {
		policy, _ := tr.Policy(account.Account)
		desc, digest, err := pqcrypto.DecodeTargetDescriptor(account.Target)
		if err != nil || policy == nil || digest.Hex() != policy.TargetDescriptorDigest ||
			desc.AccountID != account.Account || desc.DeploymentID != tr.DeploymentID() {
			return nil, errors.New("the target does not match its signed policy")
		}
		if len(account.Envelope) != 0 {
			env, err := tr.VerifyEnvelope(account.Envelope, pqcrypto.EnvelopeContext{})
			if err != nil {
				return nil, err
			}
			if env.Scope.ID != account.Account {
				return nil, errors.New("the credential envelope belongs to a different account")
			}
			chain = pqcrypto.NewChain(env)
			for _, receipt := range account.Receipts {
				if _, err := tr.Append(chain, receipt, pqcrypto.ReceiptContext{}); err != nil {
					return nil, err
				}
			}
			if !chain.Current() {
				return nil, errors.New("the credential envelope is not committed")
			}
		}
		out["target"] = map[string]any{"host": desc.Endpoint.Host, "port": desc.Endpoint.Port, "identity": desc.AuthenticatedTargetIdentity,
			"connector": desc.ConnectorType, "digest": digest.Hex()}
		out["ttl"] = policy.MaxCheckoutTTLSeconds
		out["approvals"] = policy.RequiredApproverCount
		enrolled := v.keyActive(tr, v.key)
		out["can_enroll"] = enrolled && slices.Contains(policy.EnrollerPrincipalIDs, v.key.Principal)
		out["can_checkout"] = enrolled && policy.CheckoutMode == pqcrypto.ModeEphemeral && chain != nil &&
			chain.Envelope.Policy.TargetDescriptorDigest == policy.TargetDescriptorDigest && slices.Contains(policy.AllowedUserPrincipalIDs, v.key.Principal)
		out["can_approve"] = enrolled && slices.Contains(policy.AllowedApproverPrincipalIDs, v.key.Principal)
	}
	v.trust, v.account, v.current = tr, account, chain
	return out, nil
}

func (v *worker) wrappingSecret(r request, e pqcrypto.KeyEnvelope) ([]byte, error) {
	if e.Method == vaultclient.Passphrase {
		return []byte(r.Passphrase), nil
	}
	if e.Method == vaultclient.SuiteKeyring && v.handoff != nil && v.suiteUser == r.User &&
		v.handoff.Issuer == r.Issuer && v.handoff.Subject == r.Subject && e.Ring == v.handoff.Ring && e.KeyVersion == v.handoff.KeyVersion {
		return slices.Clone(v.suiteKey), nil
	}
	return nil, errors.New("sign in with the KyIdentity keyring that wrapped this key")
}

func (v *worker) newKey(r request) (any, error) {
	for _, rec := range v.trust.Records() {
		if m, ok := rec.Manifest.(*pqcrypto.KeyEnrollmentManifest); ok && m.Issuer == r.Issuer && m.Subject == r.Subject {
			return nil, errors.New("this identity already has an enrolled KyGuard key")
		}
	}
	key, draft, err := vaultclient.CreateKey(v.trust.DeploymentID(), r.Issuer, r.Subject)
	if err != nil {
		return nil, err
	}
	e := pqcrypto.KeyEnvelope{Method: r.Method}
	if r.Method == vaultclient.SuiteKeyring && v.handoff != nil {
		e.Ring, e.KeyVersion = v.handoff.Ring, v.handoff.KeyVersion
	}
	secret, err := v.wrappingSecret(r, e)
	if err != nil {
		return nil, err
	}
	defer clear(secret)
	e, err = vaultclient.SealKey(key, draft, e.Method, e.Ring, e.KeyVersion, secret)
	if err != nil {
		return nil, err
	}
	raw, err := canonical.Marshal(draft)
	return map[string]any{"enrollment": pqcrypto.B64(raw), "sealed": e}, err
}

func (v *worker) unlock(r request) error {
	var m pqcrypto.KeyEnrollmentManifest
	if _, err := canonical.Decode(r.Enrollment, &m); err != nil {
		return err
	}
	if m.DeploymentID != v.trust.DeploymentID() || m.Issuer != r.Issuer || m.Subject != r.Subject {
		return errors.New("the encrypted key belongs to a different identity")
	}
	if err := v.trust.Check(r.Enrollment); err != nil && err != pqcrypto.ErrThreshold {
		return err
	}
	secret, err := v.wrappingSecret(r, r.Sealed)
	if err != nil {
		return err
	}
	defer clear(secret)
	key, err := vaultclient.OpenKey(r.Sealed, &m, secret)
	if err == nil {
		v.key = key
	}
	return err
}

func (v *worker) keyActive(tr *pqcrypto.Trust, key *vaultclient.UserKey) bool {
	if key == nil {
		return false
	}
	m := tr.Enrollment(key.Principal)
	if m == nil {
		return false
	}
	sig, err := key.Sign.Public().SigKeyID()
	k := m.ActiveEncKey(pqcrypto.HexID(key.Enc.Public().ID()))
	return err == nil && k != nil && k.SigKeyID == sig
}

func (v *worker) accountAction(r request) (any, error) {
	if v.account == nil || !v.keyActive(v.trust, v.key) {
		return nil, errors.New("this account and an active user key must be verified")
	}
	id := v.account.Account
	p, _ := v.trust.Policy(id)
	now := time.Now().UTC()
	switch r.Action {
	case "reserve":
		if !slices.Contains(p.EnrollerPrincipalIDs, v.key.Principal) {
			return nil, pqcrypto.ErrNotAllowed
		}
		reservation, err := uuid.NewV7()
		if err != nil {
			return nil, err
		}
		return vaultclient.SignReservation(v.trust, id, pqcrypto.UUID(reservation.String()), v.key.Principal, v.key.Sign, now)
	case "enroll":
		pw := []byte(r.Password)
		defer clear(pw)
		e, err := vaultclient.SealEnrollment(v.trust, id, r.Reservation, r.Version, v.key.Principal, v.key.Sign, pw, now)
		if err != nil {
			return nil, err
		}
		return map[string]pqcrypto.B64{"tx": e.Tx, "envelope": e.Envelope}, nil
	case "checkout":
		if p.CheckoutMode != pqcrypto.ModeEphemeral || !slices.Contains(p.AllowedUserPrincipalIDs, v.key.Principal) ||
			v.current == nil || v.current.Envelope.Policy.TargetDescriptorDigest != p.TargetDescriptorDigest ||
			r.TTL < 1 || r.TTL > p.MaxCheckoutTTLSeconds {
			return nil, pqcrypto.ErrNotAllowed
		}
		a := pqcrypto.Action{ActionType: pqcrypto.ActionVaultCheckout, AccountID: id, SecretVersion: v.current.Envelope.SecretVersion,
			EncKeyID: pqcrypto.HexID(v.key.Enc.Public().ID()), CheckoutTTLSeconds: r.TTL}
		c, err := vaultclient.NewTransaction(v.trust, a, v.key.Principal, v.key.Sign, now)
		if err != nil {
			return nil, err
		}
		v.checkout, v.leaseEnvelope = c, v.account.Envelope
		return map[string]any{"request_id": c.RequestID, "tx": pqcrypto.B64(c.Tx)}, nil
	default:
		return v.approval(r, now)
	}
}

func (v *worker) approval(r request, now time.Time) (any, error) {
	id := v.account.Account
	p, _ := v.trust.Policy(id)
	pool := v.trust.Pool(p.PoolID)
	if pool == nil || pool.Active() == nil {
		return nil, pqcrypto.ErrNotAllowed
	}
	var candidate pqcrypto.AccessTransaction
	if _, err := canonical.Decode(r.Tx, &candidate); err != nil {
		return nil, err
	}
	adding := r.Action == "approve" || r.Action == "review-approval"
	verification := pqcrypto.TxContext{BrokerID: pool.Active().BrokerID, Now: now,
		Seen: func(pqcrypto.UUID) bool { return false }, AllowPartialApprovals: adding}
	if v.current != nil {
		verification.Current = &pqcrypto.CurrentEnvelope{SecretVersion: v.current.Envelope.SecretVersion}
		verification.HighestVersion = v.current.Envelope.SecretVersion
	}
	switch candidate.Action.ActionType {
	case pqcrypto.ActionEnroll:
		verification.CandidateVersion, verification.CandidateDigest = candidate.Action.SecretVersion, candidate.Action.EnvelopeDigest
	case pqcrypto.ActionVaultCheckout:
	default:
		return nil, pqcrypto.ErrNotAllowed
	}
	tx, digest, err := v.trust.VerifyTx(r.Tx, verification)
	if err != nil {
		return nil, err
	}
	if tx.Scope.ID != id {
		return nil, pqcrypto.ErrNotAllowed
	}
	if adding {
		if !slices.Contains(p.AllowedApproverPrincipalIDs, v.key.Principal) || tx.RequesterPrincipalID == v.key.Principal ||
			slices.ContainsFunc(tx.Approvals, func(a pqcrypto.Approval) bool { return a.ApproverPrincipalID == v.key.Principal }) {
			return nil, pqcrypto.ErrNotAllowed
		}
		if r.Action == "review-approval" {
			requester := v.trust.Enrollment(tx.RequesterPrincipalID)
			return map[string]any{"requester": requester.Subject, "issuer": requester.Issuer,
				"ttl": tx.Action.CheckoutTTLSeconds, "action": tx.Action.ActionType}, nil
		}
		if err := tx.Approve(v.key.Principal, v.key.Sign); err != nil {
			return nil, err
		}
	} else {
		if tx.RequesterPrincipalID != v.key.Principal {
			return nil, pqcrypto.ErrStale
		}
		originalBytes := r.Original
		if tx.Action.ActionType == pqcrypto.ActionVaultCheckout {
			if v.checkout == nil || v.checkout.RequestID != tx.RequestID {
				return nil, pqcrypto.ErrStale
			}
			originalBytes = v.checkout.Tx
		}
		var original pqcrypto.AccessTransaction
		if _, err := canonical.Decode(originalBytes, &original); err != nil {
			return nil, err
		}
		d, err := pqcrypto.ObjDigest(&original)
		if err != nil || d != digest {
			return nil, pqcrypto.ErrStale
		}
	}
	raw, err := canonical.Marshal(tx)
	if err == nil && !adding && tx.Action.ActionType == pqcrypto.ActionVaultCheckout {
		v.checkout.Tx = raw
	}
	return pqcrypto.B64(raw), err
}
