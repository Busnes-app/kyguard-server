package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// pendingSession authenticates a request that must come from a pending SSO session.
func (s *Server) pendingSession(w http.ResponseWriter, r *http.Request) (*store.User, *store.Session, bool) {
	user, sess, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return nil, nil, false
	}
	if sess.Stage != store.StagePending {
		s.writeError(w, http.StatusConflict, "This session has already stepped up")
		return nil, nil, false
	}
	return user, sess, true
}

func (s *Server) readCode(w http.ResponseWriter, r *http.Request) (string, bool) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		s.writeError(w, http.StatusBadRequest, "An authenticator code is required")
		return "", false
	}
	return req.Code, true
}

// stepupAudit writes a step-up audit record; a failed write fails the request.
func (s *Server) stepupAudit(w http.ResponseWriter, r *http.Request, userID, action, details string) bool {
	if err := detachedWrite(r, func(ctx context.Context) error {
		return s.store.Audit().LogAudit(ctx, &store.AuditRecord{UserID: userID, Action: action, Resource: "session", Details: details, IPAddress: s.requestIP(r)})
	}); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Audit unavailable")
		return false
	}
	return true
}

// codeRefused answers a refused or failed code check, auditing every refusal (spec §7.3 rule 5).
func (s *Server) codeRefused(w http.ResponseWriter, r *http.Request, userID string, err error) {
	if !errors.Is(err, auth.ErrCodeRejected) {
		s.writeError(w, http.StatusServiceUnavailable, "Authentication temporarily unavailable")
		return
	}
	if s.stepupAudit(w, r, userID, "auth.stepup_failed", "severity=warning") {
		s.writeError(w, http.StatusUnauthorized, "Authenticator code is incorrect")
	}
}

// exchanged answers a pending-to-active exchange.
func (s *Server) exchanged(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		s.writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
	case errors.Is(err, store.ErrSSOSessionEnded):
		s.writeError(w, http.StatusUnauthorized, "Your identity provider ended this sign-in")
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusUnauthorized, "This sign-in expired; sign in again")
	default:
		s.writeError(w, http.StatusServiceUnavailable, "Step-up temporarily unavailable")
	}
}

// handleStepupTOTP exchanges a pending session for an active one with a valid TOTP code
// (spec §7.3 rule 2).
func (s *Server) handleStepupTOTP(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	code, ok := s.readCode(w, r)
	if !ok {
		return
	}
	factorID, err := s.factors.Check(r.Context(), user.ID, sess.TokenHash, code)
	if err != nil {
		s.codeRefused(w, r, user.ID, err)
		return
	}
	err = detachedWrite(r, func(ctx context.Context) error {
		_, _, err := s.sessions.ExchangePending(ctx, w, r, user, sess, factorID, nil,
			&store.AuditRecord{UserID: user.ID, Action: "auth.stepup", Resource: "session", Details: "factor=totp", IPAddress: s.requestIP(r)})
		return err
	})
	s.exchanged(w, err)
}

// handleStepupEnroll offers a first TOTP factor to a pending session whose ID token asserted
// MFA (spec §7.3 rule 3). Without IdP MFA the user is blocked and admins are told through the
// audit log.
func (s *Server) handleStepupEnroll(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	if _, err := s.store.MFA().GetFactor(r.Context(), user.ID, store.FactorTOTP); err == nil {
		s.writeError(w, http.StatusConflict, "An authenticator is already enrolled; enter its code")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusServiceUnavailable, "Enrollment temporarily unavailable")
		return
	}
	if !sess.MFAAsserted {
		if s.stepupAudit(w, r, user.ID, "auth.enrollment_blocked", "severity=critical reason=no_idp_mfa") {
			s.writeError(w, http.StatusForbidden, "Your identity provider did not confirm multi-factor sign-in, so an authenticator cannot be enrolled. An administrator has been notified.")
		}
		return
	}
	secret, sealed, err := s.factors.NewSecret(user.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "Enrollment failed")
		return
	}
	if err := s.store.Sessions().SetPendingSecret(r.Context(), sess.TokenHash, sealed); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "Enrollment temporarily unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_uri": totp.ProvisioningURI(s.config.Server.AppName, user.Username, secret)})
}

// handleStepupEnrollConfirm stores the offered factor once a code from it verifies, and
// performs the exchange in the same transaction.
func (s *Server) handleStepupEnrollConfirm(w http.ResponseWriter, r *http.Request) {
	user, sess, ok := s.pendingSession(w, r)
	if !ok {
		return
	}
	code, ok := s.readCode(w, r)
	if !ok {
		return
	}
	counter, err := s.factors.CheckEnrollment(r.Context(), user.ID, sess.TokenHash, sess.PendingSecretEnc, code)
	if err != nil {
		s.codeRefused(w, r, user.ID, err)
		return
	}
	factor := &store.MFAFactor{ID: "mfa_" + crypto.RandomHex(12), SecretEnc: sess.PendingSecretEnc, LastCounter: counter}
	err = detachedWrite(r, func(ctx context.Context) error {
		_, _, err := s.sessions.ExchangePending(ctx, w, r, user, sess, "", factor,
			&store.AuditRecord{UserID: user.ID, Action: "auth.factor_enrolled", Resource: "session", Details: "factor=totp", IPAddress: s.requestIP(r)})
		return err
	})
	if errors.Is(err, store.ErrAlreadyExists) {
		s.writeError(w, http.StatusConflict, "An authenticator is already enrolled; enter its code")
		return
	}
	s.exchanged(w, err)
}
