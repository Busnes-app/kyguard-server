package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"

	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func (s *Server) draftRoutes() {
	// TODO(hawthorn §7.5): classify + fresh(StepupWindow) (5 minutes for policy drafts, §7.3 rule 6).
	s.mux.HandleFunc("PUT /api/accounts/{id}/policy-draft", s.requireAdmin(s.handlePutDraft))
	// TODO(hawthorn §7.5): classify + fresh(StepupWindow).
	s.mux.HandleFunc("DELETE /api/policy-drafts/{id}", s.requireAdmin(s.handleDeleteDraft))
	// TODO(hawthorn §7.5): classify (session). Custodians fetch and sign from kyguard-cli.
	s.mux.HandleFunc("GET /api/policy-drafts", s.requireAuthenticated(s.handleListDrafts))
	s.mux.HandleFunc("GET /api/policy-drafts/{id}", s.requireAuthenticated(s.handleGetDraft))
	// Signatures carry their own authority; the session only identifies the submitter.
	s.mux.HandleFunc("POST /api/policy-drafts/{id}/signatures", s.requireAuthenticated(s.handleSignDraft))
	s.mux.HandleFunc("GET /api/principals", s.requireAdmin(s.handleListPrincipals))
	s.mux.HandleFunc("GET /api/trust", s.requireAuthenticated(s.handleTrustSummary))
}

type draftRequest struct {
	CheckoutMode                  string             `json:"checkout_mode"`
	TargetDescriptorDigest        pqcrypto.HexID     `json:"target_descriptor_digest"`
	EnrollerPrincipalIDs          []pqcrypto.UUID    `json:"enroller_principal_ids"`
	AutoStandingRelease           bool               `json:"auto_standing_release"`
	StandingRecipientPrincipalIDs []pqcrypto.UUID    `json:"standing_recipient_principal_ids"`
	AllowedUserPrincipalIDs       []pqcrypto.UUID    `json:"allowed_user_principal_ids"`
	AllowedApproverPrincipalIDs   []pqcrypto.UUID    `json:"allowed_approver_principal_ids"`
	RequiredApproverCount         int                `json:"required_approver_count"`
	MaxCheckoutTTLSeconds         int64              `json:"max_checkout_ttl_seconds"`
	RotationSchedule              *pqcrypto.Schedule `json:"rotation_schedule"`
	RecoveryEscrowEnabled         bool               `json:"recovery_escrow_enabled"`
}

func orEmpty(ids []pqcrypto.UUID) []pqcrypto.UUID {
	if ids == nil {
		return []pqcrypto.UUID{}
	}
	return ids
}

func (s *Server) refuse(w http.ResponseWriter, err error) {
	var perr pqcrypto.Error
	switch {
	case errors.Is(err, cptrust.ErrNoBundle):
		s.writeError(w, http.StatusServiceUnavailable, "import the bootstrap bundle first")
	case errors.As(err, &perr):
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "policy refused", "code": string(perr)})
	default:
		s.writeError(w, http.StatusInternalServerError, "could not check the policy")
	}
}

// handlePutDraft builds the account's next PolicyManifest from the form, checks it against
// the verified state exactly as Accept would (short of signatures) and stores it for
// Custodian signing (spec §3.3, §10). It replaces any earlier draft and its signatures.
func (s *Server) handlePutDraft(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := s.store.Inventory().GetAccount(ctx, r.PathValue("id"))
	if err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	var req draftRequest
	if err := decodeStrict(r, &req); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid policy draft")
		return
	}
	pm := &pqcrypto.PolicyManifest{AccountID: pqcrypto.UUID(a.ID), AccountKind: a.AccountKind,
		AllowedUserPrincipalIDs: orEmpty(req.AllowedUserPrincipalIDs), AllowedApproverPrincipalIDs: orEmpty(req.AllowedApproverPrincipalIDs),
		RequiredApproverCount: req.RequiredApproverCount, MaxCheckoutTTLSeconds: req.MaxCheckoutTTLSeconds, RecoveryEscrowEnabled: req.RecoveryEscrowEnabled,
		Sigs: pqcrypto.Sigs{Signatures: []pqcrypto.Signature{}}}
	if a.AccountKind == pqcrypto.KindManaged {
		if a.PoolID == "" {
			s.writeError(w, http.StatusBadRequest, "a managed account needs a broker pool")
			return
		}
		descs, err := s.store.Inventory().Descriptors(ctx, a.ID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "could not read descriptors")
			return
		}
		if !slices.ContainsFunc(descs, func(d *store.StoredDescriptor) bool { return d.Digest == string(req.TargetDescriptorDigest) }) {
			s.writeError(w, http.StatusBadRequest, "target_descriptor_digest is not an uploaded descriptor of this account")
			return
		}
		auto := req.AutoStandingRelease
		pm.PoolID, pm.TargetDescriptorDigest, pm.CheckoutMode = pqcrypto.UUID(a.PoolID), req.TargetDescriptorDigest, req.CheckoutMode
		pm.EnrollerPrincipalIDs, pm.AutoStandingRelease, pm.StandingRecipientPrincipalIDs = orEmpty(req.EnrollerPrincipalIDs), &auto, orEmpty(req.StandingRecipientPrincipalIDs)
		pm.RotationSchedule = req.RotationSchedule
	} else if req.CheckoutMode != "" || req.TargetDescriptorDigest != "" || req.EnrollerPrincipalIDs != nil || req.AutoStandingRelease ||
		req.StandingRecipientPrincipalIDs != nil || req.RotationSchedule != nil {
		s.writeError(w, http.StatusBadRequest, "a vaulted policy has no checkout mode, target, enrollers, standing release or schedule")
		return
	}

	var raw []byte
	var digest pqcrypto.Digest
	err = s.trust.View(ctx, func(tr *pqcrypto.Trust) error {
		epoch := pqcrypto.Counter(1)
		if cur, _ := tr.Policy(pm.AccountID); cur != nil {
			epoch = cur.Epoch + 1
		}
		pm.Header = pqcrypto.Header{Type: pqcrypto.TypePolicy, DeploymentID: tr.DeploymentID(), Epoch: epoch,
			Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: pm.AccountID}, SignerRole: pqcrypto.RoleCustodian}
		// Every principal must be enrolled: a broker can verify no one else (§3.4).
		for _, l := range [][]pqcrypto.UUID{pm.AllowedUserPrincipalIDs, pm.AllowedApproverPrincipalIDs, pm.EnrollerPrincipalIDs, pm.StandingRecipientPrincipalIDs} {
			for _, id := range l {
				if tr.Enrollment(id) == nil {
					return pqcrypto.Error("unknown_principal")
				}
			}
		}
		var err error
		if raw, err = canonical.Marshal(pm); err != nil {
			return err
		}
		if digest, err = pqcrypto.D(pqcrypto.TypePolicy, pm); err != nil {
			return err
		}
		if err := tr.Check(raw); !errors.Is(err, pqcrypto.ErrThreshold) {
			if err == nil {
				err = pqcrypto.Error("unsigned_accepted") // a custodian set of M = 0 cannot exist
			}
			return err
		}
		return nil
	})
	if err != nil {
		s.refuse(w, err)
		return
	}
	d := &store.PolicyDraft{ID: newID(), AccountID: a.ID, Epoch: uint64(pm.Epoch), Digest: string(digest.Hex()), Object: raw, CreatedBy: s.actor(r)}
	if err := s.store.Drafts().PutDraft(ctx, d, s.audit(r, "policy.draft_saved", "account:"+a.ID,
		map[string]any{"epoch": d.Epoch, "digest": d.Digest})); err != nil {
		s.inventoryError(w, err, "policy draft")
		return
	}
	s.writeJSON(w, http.StatusCreated, d)
}

type draftView struct {
	*store.PolicyDraft
	Account    string `json:"account"`
	Signatures int    `json:"signatures"`
	// Status is needs_signatures; ready when fully signed (an admission was interrupted; a
	// retry admits it); or stale (with Code) once the draft can never be accepted:
	// another policy was accepted meanwhile, or a principal or pool changed.
	Status string `json:"status"`
	Code   string `json:"code,omitempty"`
}

func (s *Server) viewDraft(tr *pqcrypto.Trust, d *store.PolicyDraft, account string) draftView {
	v := draftView{PolicyDraft: d, Account: account, Status: "needs_signatures"}
	var sigs pqcrypto.Sigs
	if json.Unmarshal(d.Object, &sigs) == nil {
		v.Signatures = len(sigs.Signatures)
	}
	switch err := tr.Check(d.Object); {
	case err == nil: // fully signed; an earlier admission was interrupted, so a retry admits it
		v.Status = "ready"
	case !errors.Is(err, pqcrypto.ErrThreshold):
		v.Status = "stale"
		var perr pqcrypto.Error
		if errors.As(err, &perr) {
			v.Code = string(perr)
		}
	}
	return v
}

func (s *Server) handleListDrafts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	drafts, err := s.store.Drafts().ListDrafts(ctx)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list drafts")
		return
	}
	out := []draftView{}
	err = s.trust.View(ctx, func(tr *pqcrypto.Trust) error {
		for _, d := range drafts {
			name := ""
			if a, err := s.store.Inventory().GetAccount(ctx, d.AccountID); err == nil {
				name = a.AssetName + " / " + a.Name
			}
			out = append(out, s.viewDraft(tr, d, name))
		}
		return nil
	})
	if err != nil && !errors.Is(err, cptrust.ErrNoBundle) {
		s.writeError(w, http.StatusInternalServerError, "could not check drafts")
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleGetDraft returns the object to sign with the descriptor it pins and the Control
// Plane's labels, which kyguard-cli shows as unverified (spec §3.2 rule 4).
func (s *Server) handleGetDraft(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := s.store.Drafts().GetDraft(ctx, r.PathValue("id"))
	if err != nil {
		s.inventoryError(w, err, "policy draft")
		return
	}
	a, err := s.store.Inventory().GetAccount(ctx, d.AccountID)
	if err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	var pm pqcrypto.PolicyManifest
	if err := json.Unmarshal(d.Object, &pm); err != nil {
		s.writeError(w, http.StatusInternalServerError, "stored draft does not decode")
		return
	}
	var target json.RawMessage
	if pm.TargetDescriptorDigest != "" {
		descs, err := s.store.Inventory().Descriptors(ctx, a.ID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "could not read descriptors")
			return
		}
		for _, t := range descs {
			if t.Digest == string(pm.TargetDescriptorDigest) {
				target = t.Descriptor
			}
		}
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"draft": d, "object": json.RawMessage(d.Object), "target": target,
		"labels": map[string]string{"account": a.Name, "asset": a.AssetName}})
}

// handleSignDraft takes the draft back with more Custodian signatures. The object must have
// the stored digest and keep every stored signature; at quorum it is submitted as a
// manifest and the draft is removed (spec §3.2 rule 1).
func (s *Server) handleSignDraft(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	d, err := s.store.Drafts().GetDraft(ctx, r.PathValue("id"))
	if err != nil {
		s.inventoryError(w, err, "policy draft")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxManifestBody))
	if err != nil {
		s.writeError(w, http.StatusRequestEntityTooLarge, "draft too large")
		return
	}
	var pm pqcrypto.PolicyManifest
	canon, err := canonical.Decode(raw, &pm)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "signed draft does not decode")
		return
	}
	dg, err := pqcrypto.D(pqcrypto.TypePolicy, &pm)
	if err != nil || string(dg.Hex()) != d.Digest {
		s.writeError(w, http.StatusConflict, "signed object is not this draft")
		return
	}
	var have pqcrypto.Sigs
	if err := json.Unmarshal(d.Object, &have); err != nil {
		s.writeError(w, http.StatusInternalServerError, "stored draft does not decode")
		return
	}
	for _, sg := range have.Signatures {
		if !slices.ContainsFunc(pm.Signatures, func(x pqcrypto.Signature) bool { return x.SigKeyID == sg.SigKeyID && x.SignerRole == sg.SignerRole }) {
			s.writeError(w, http.StatusConflict, "signed object drops a collected signature")
			return
		}
	}
	var complete bool
	err = s.trust.View(ctx, func(tr *pqcrypto.Trust) error {
		err := tr.Check(canon)
		complete = err == nil
		if errors.Is(err, pqcrypto.ErrThreshold) {
			return nil
		}
		return err
	})
	if err != nil {
		s.refuse(w, err)
		return
	}
	audit := s.audit(r, "policy.draft_signed", "account:"+d.AccountID, map[string]any{"digest": d.Digest, "signatures": len(pm.Signatures), "complete": complete})
	if !complete {
		if err := s.store.Drafts().SetDraftObject(ctx, d.ID, d.Object, canon, audit); errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, "the draft changed meanwhile; fetch it again and re-sign")
			return
		} else if err != nil {
			s.inventoryError(w, err, "policy draft")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"accepted": false, "signatures": len(pm.Signatures)})
		return
	}
	// Keep the signed object first, by compare-and-swap on the object checked: a draft
	// replaced or deleted meanwhile is never admitted, and an interrupted or failed admission
	// leaves the signatures stored for a retry. Only an admitted policy consumes its draft.
	if err := s.store.Drafts().SetDraftObject(ctx, d.ID, d.Object, canon, nil); errors.Is(err, store.ErrConflict) {
		s.writeError(w, http.StatusConflict, "the draft changed meanwhile; fetch it again and re-sign")
		return
	} else if err != nil {
		s.inventoryError(w, err, "policy draft")
		return
	}
	if _, _, err := s.trust.Submit(ctx, canon, s.actor(r), s.requestIP(r)); err != nil {
		s.refuse(w, err)
		return
	}
	if err := s.store.Drafts().TakeDraft(ctx, d.ID, canon, audit); err != nil && !errors.Is(err, store.ErrConflict) {
		s.writeError(w, http.StatusInternalServerError, "policy accepted; the draft could not be removed")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"accepted": true, "epoch": pm.Epoch.String(), "digest": d.Digest})
}

func (s *Server) handleDeleteDraft(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Drafts().DeleteDraft(r.Context(), id, s.audit(r, "policy.draft_deleted", "draft:"+id, nil)); err != nil {
		s.inventoryError(w, err, "policy draft")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type principalView struct {
	PrincipalID string `json:"principal_id"`
	Issuer      string `json:"issuer"`
	Subject     string `json:"subject"`
	ActiveKeys  int    `json:"active_keys"`
}

// handleListPrincipals lists the verified key enrollments a policy can name.
func (s *Server) handleListPrincipals(w http.ResponseWriter, r *http.Request) {
	out := []principalView{}
	err := s.trust.View(r.Context(), func(tr *pqcrypto.Trust) error {
		for _, rec := range tr.Records() {
			if rec.Type != pqcrypto.TypeKeyEnrollment {
				continue
			}
			ke := tr.Enrollment(rec.ScopeID)
			if ke == nil || slices.ContainsFunc(out, func(p principalView) bool { return p.PrincipalID == string(ke.PrincipalID) }) {
				continue
			}
			v := principalView{PrincipalID: string(ke.PrincipalID), Issuer: ke.Issuer, Subject: ke.Subject}
			for _, k := range ke.Keys {
				if k.Status == pqcrypto.StatusActive {
					v.ActiveKeys++
				}
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil && !errors.Is(err, cptrust.ErrNoBundle) {
		s.writeError(w, http.StatusInternalServerError, "could not read principals")
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}

// handleTrustSummary tells the dashboard the custodian threshold (it warns on 1 of 1, §10)
// and the escrow default for new drafts.
func (s *Server) handleTrustSummary(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{"imported": false}
	err := s.trust.View(r.Context(), func(tr *pqcrypto.Trust) error {
		cs, rk := tr.CustodianSet(), tr.RecoveryKey()
		out = map[string]any{"imported": true, "fingerprint": tr.Fingerprint(), "threshold": cs.Threshold,
			"custodians": len(cs.Custodians), "escrow_default_enabled": rk.EscrowDefaultEnabled}
		return nil
	})
	if err != nil && !errors.Is(err, cptrust.ErrNoBundle) {
		s.writeError(w, http.StatusInternalServerError, "could not read the trust state")
		return
	}
	s.writeJSON(w, http.StatusOK, out)
}
