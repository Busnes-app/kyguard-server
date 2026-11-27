package api

import (
	"errors"
	"net/http"
	"slices"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

type browserKeyUpload struct {
	Enrollment pqcrypto.B64         `json:"enrollment"`
	Sealed     pqcrypto.KeyEnvelope `json:"sealed"`
}

func (s *Server) browserVaultRoutes() {
	s.route(ClassSession, "GET /api/user/vault-key", http.HandlerFunc(s.handleBrowserKey))
	s.route(ClassSession, "PUT /api/user/vault-key", http.HandlerFunc(s.handleStoreBrowserKey), fresh(StepupWindow))
	s.route(ClassSession, "GET /api/accounts/{id}/vault-context", http.HandlerFunc(s.handleBrowserVaultContext))
}

func (s *Server) browserVaultUser(w http.ResponseWriter, r *http.Request) *store.User {
	w.Header().Set("Cache-Control", "no-store")
	if !s.config.Server.BrowserVault {
		s.writeError(w, http.StatusNotFound, "Browser vault is disabled")
		return nil
	}
	user, _, err := s.sessions.AuthenticateRequest(r)
	if err != nil || user.SSOIssuer == "" || user.SSOSubject == "" || user.AccountType == store.AccountBreakGlass {
		s.writeError(w, http.StatusForbidden, "The browser vault requires an SSO account")
		return nil
	}
	return user
}

func (s *Server) handleBrowserKey(w http.ResponseWriter, r *http.Request) {
	user := s.browserVaultUser(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	bundle, err := s.store.Guard().Bundle(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Deployment trust bundle is unavailable")
		return
	}
	out := map[string]any{"issuer": user.SSOIssuer, "subject": user.SSOSubject,
		"bundle": pqcrypto.B64(bundle.Bundle), "manifests": []pqcrypto.B64{}}
	key, err := s.store.Guard().BrowserKey(ctx, user)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusServiceUnavailable, "Could not read the encrypted user key")
		return
	}
	var manifests []pqcrypto.B64
	err = s.trust.View(ctx, func(tr *pqcrypto.Trust) error {
		for _, rec := range tr.Records() {
			enrollment, isEnrollment := rec.Manifest.(*pqcrypto.KeyEnrollmentManifest)
			if rec.Type == pqcrypto.TypeCustodianSet || rec.Type == pqcrypto.TypeRecoveryKey ||
				(isEnrollment && enrollment.Issuer == user.SSOIssuer && enrollment.Subject == user.SSOSubject) {
				manifests = append(manifests, pqcrypto.B64(rec.Canonical))
			}
		}
		return nil
	})
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Could not read deployment trust")
		return
	}
	if len(manifests) > 0 {
		out["manifests"] = manifests
	}
	if key != nil {
		out["enrollment"] = pqcrypto.B64(key.Enrollment)
		var sealed pqcrypto.KeyEnvelope
		if _, err := canonical.Decode([]byte(key.Sealed), &sealed); err != nil || !sealed.Valid() {
			s.writeError(w, http.StatusInternalServerError, "Encrypted user key is invalid")
			return
		}
		out["sealed"] = sealed
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleStoreBrowserKey(w http.ResponseWriter, r *http.Request) {
	user := s.browserVaultUser(w, r)
	if user == nil {
		return
	}
	var req browserKeyUpload
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if decodeStrict(r, &req) != nil || !req.Sealed.Valid() {
		s.writeError(w, http.StatusBadRequest, "Expected a sealed KyGuard user key and signed enrollment")
		return
	}
	if req.Sealed.Method == pqcrypto.BrowserSuiteKeyring && (!s.keyringEnabled() || user.SSOProvider != "kysignon") {
		s.writeError(w, http.StatusForbidden, "Suite keyring is unavailable for this account")
		return
	}
	object, digest, err := pqcrypto.DecodeManifest(req.Enrollment)
	enrollment, ok := object.(*pqcrypto.KeyEnrollmentManifest)
	if err != nil || !ok || enrollment.Epoch != 1 || len(enrollment.Keys) != 1 ||
		enrollment.Keys[0].Status != pqcrypto.StatusActive || enrollment.Issuer != user.SSOIssuer || enrollment.Subject != user.SSOSubject {
		s.writeError(w, http.StatusUnprocessableEntity, "The enrollment must name your SSO identity and one active user key")
		return
	}
	err = s.trust.View(r.Context(), func(tr *pqcrypto.Trust) error {
		for _, rec := range tr.Records() {
			if m, ok := rec.Manifest.(*pqcrypto.KeyEnrollmentManifest); ok &&
				m.Issuer == user.SSOIssuer && m.Subject == user.SSOSubject && m.PrincipalID != enrollment.PrincipalID {
				return store.ErrConflict
			}
		}
		err := tr.Check(req.Enrollment)
		if err == pqcrypto.ErrThreshold {
			return nil // The user's self-signature is required even before Custodian approval.
		}
		return err
	})
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeError(w, http.StatusConflict, "This identity already has a different enrolled key")
		return
	case err != nil:
		s.writeError(w, http.StatusUnprocessableEntity, "The enrollment signature or deployment is invalid")
		return
	}
	sealed, err := canonical.Marshal(req.Sealed)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "Invalid encrypted user key")
		return
	}
	err = s.store.Guard().PutBrowserKey(r.Context(), user, store.BrowserKey{Enrollment: string(req.Enrollment), Sealed: string(sealed)},
		&store.AuditRecord{UserID: user.ID, Action: "vault.browser_key_created", Resource: string(enrollment.PrincipalID),
			Details: "enrollment_digest=" + string(digest.Hex()), IPAddress: s.requestIP(r)})
	switch {
	case errors.Is(err, store.ErrConflict):
		s.writeError(w, http.StatusConflict, "A browser key already exists")
	case err != nil:
		s.writeError(w, http.StatusServiceUnavailable, "Could not save the encrypted user key")
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleBrowserVaultContext(w http.ResponseWriter, r *http.Request) {
	user := s.browserVaultUser(w, r)
	if user == nil {
		return
	}
	ctx := r.Context()
	account := pqcrypto.UUID(r.PathValue("id"))
	manifests := []pqcrypto.B64{}
	var descriptor pqcrypto.HexID
	err := s.trust.View(ctx, func(tr *pqcrypto.Trust) error {
		policy, _ := tr.Policy(account)
		if policy == nil || policy.AccountKind != pqcrypto.KindManaged {
			return store.ErrNotFound
		}
		descriptor = policy.TargetDescriptorDigest
		var allowed bool
		principals := map[pqcrypto.UUID]bool{}
		pools := map[pqcrypto.UUID]bool{}
		for _, list := range [][]pqcrypto.UUID{policy.AllowedUserPrincipalIDs, policy.EnrollerPrincipalIDs, policy.AllowedApproverPrincipalIDs} {
			for _, p := range list {
				if m := tr.Enrollment(p); m != nil && m.Issuer == user.SSOIssuer && m.Subject == user.SSOSubject {
					allowed = true
				}
			}
		}
		if !allowed {
			return store.ErrNotFound
		}
		// Include the signed history needed to verify a still-current older envelope.
		records := tr.Records()
		for _, rec := range records {
			if p, ok := rec.Manifest.(*pqcrypto.PolicyManifest); ok && rec.ScopeID == account {
				pools[p.PoolID] = true
				for _, principal := range slices.Concat(p.AllowedUserPrincipalIDs, p.EnrollerPrincipalIDs, p.AllowedApproverPrincipalIDs, p.StandingRecipientPrincipalIDs) {
					principals[principal] = true
				}
			}
		}
		for _, rec := range records {
			switch rec.Type {
			case pqcrypto.TypePolicy:
				if rec.ScopeID != account {
					continue
				}
			case pqcrypto.TypePool:
				if !pools[rec.ScopeID] {
					continue
				}
			case pqcrypto.TypeKeyEnrollment:
				if !principals[rec.ScopeID] {
					continue
				}
			}
			manifests = append(manifests, pqcrypto.B64(rec.Canonical))
		}
		return nil
	})
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "No vault access for this account")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Could not read account trust")
		return
	}
	a, err := s.store.Vault().GetAccount(ctx, string(account))
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.Status != "active") {
		s.writeError(w, http.StatusNotFound, "No vault access for this account")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Could not read the account")
		return
	}
	target, err := s.store.Vault().TargetDescriptor(ctx, string(descriptor))
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Could not read the target descriptor")
		return
	}
	out := map[string]any{"manifests": manifests, "target": pqcrypto.B64(target)}
	if a.CurrentEnvelopeID != "" {
		c, err := s.store.Vault().Chain(ctx, string(account), a.CurrentEnvelopeID)
		if err != nil {
			s.writeError(w, http.StatusServiceUnavailable, "Could not read the current envelope")
			return
		}
		out["envelope"] = pqcrypto.B64(c.Envelope.Envelope)
		receipts := make([]pqcrypto.B64, 0, len(c.Receipts))
		for _, receipt := range c.Receipts {
			receipts = append(receipts, pqcrypto.B64(receipt.Receipt))
		}
		out["receipts"] = receipts
	}
	s.writeJSON(w, http.StatusOK, out)
}
