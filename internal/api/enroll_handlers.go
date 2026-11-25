package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// EnrollmentReservationTTL is how long a reservation waits for the broker's acceptance
// before its lock goes back to the holder it displaced (§4.5 step 1).
const EnrollmentReservationTTL = 15 * time.Minute

// maxRequestBody caps a signed request body (an enrollment, a transaction, a proof).
const maxRequestBody = 512 << 10

func (s *Server) enrollRoutes() {
	// TODO(hawthorn §7.5): classify + step-up (fresh step-up required, §4.5).
	s.mux.HandleFunc("POST /api/accounts/{id}/enrollments", s.requireAuthenticated(s.handleReserveEnrollment))
	// TODO(hawthorn §7.5): classify + step-up (fresh step-up required, §4.5).
	s.mux.HandleFunc("POST /api/accounts/{id}/enrollments/{request}", s.requireAuthenticated(s.handleSubmitEnrollment))
	// TODO(hawthorn §7.5): classify.
	s.mux.HandleFunc("GET /api/accounts/{id}/enrollments/{request}", s.requireAuthenticated(s.handleEnrollmentStatus))
}

// activeBroker is the active broker of the account's current managed policy.
func activeBroker(tr *pqcrypto.Trust, account pqcrypto.UUID) (pqcrypto.UUID, error) {
	p, _ := tr.Policy(account)
	if p == nil || p.AccountKind != pqcrypto.KindManaged {
		return "", errors.New("no managed policy")
	}
	pool := tr.Pool(p.PoolID)
	if pool == nil || pool.Active() == nil {
		return "", errors.New("no active broker")
	}
	return pool.Active().BrokerID, nil
}

func (s *Server) handleReserveEnrollment(w http.ResponseWriter, r *http.Request) {
	var req brokerproto.EnrollReservation
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil || !req.RequestID.Valid() {
		s.writeError(w, http.StatusBadRequest, "a signed reservation is required")
		return
	}
	account := pqcrypto.UUID(r.PathValue("id"))
	var broker pqcrypto.UUID
	err := s.trust.View(r.Context(), func(tr *pqcrypto.Trust) (err error) {
		if broker, err = activeBroker(tr, account); err != nil {
			return errNoPolicy
		}
		return enrollerSigned(tr, &req, account, time.Now().UTC())
	})
	switch {
	case errors.Is(err, errNoPolicy):
		s.writeError(w, http.StatusConflict, "the account has no managed policy with an active broker")
		return
	case err != nil:
		s.writeError(w, http.StatusForbidden, "the reservation is not signed by an enroller of this account")
		return
	}
	op, err := pqcrypto.RequestOpID(req.RequestID, 0)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request_id")
		return
	}
	v, err := s.store.Vault().ReserveEnrollment(r.Context(), string(account), string(op), 0, time.Now().UTC(), EnrollmentReservationTTL)
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusNotFound, "account not found")
		return
	case errors.Is(err, store.ErrLocked):
		s.writeError(w, http.StatusConflict, "a rotation is open on a healthy account, or another enrollment is in progress")
		return
	case err != nil:
		s.writeError(w, http.StatusInternalServerError, "could not reserve")
		return
	}
	if err := s.store.Audit().LogAudit(r.Context(), &store.AuditRecord{UserID: s.actor(r), Action: "vault.enrollment_reserved", Resource: "account:" + string(account),
		Details: "operation_id=" + string(op) + " secret_version=" + pqcrypto.Counter(v).String(), IPAddress: s.requestIP(r)}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not audit")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]string{"operation_id": string(op), "secret_version": pqcrypto.Counter(v).String(), "broker_id": string(broker)})
}

// handleSubmitEnrollment checks the CLI's enroll transaction and candidate against the
// manifests, stores the candidate under the reservation and relays both to the broker,
// which checks them again and alone decides.
func (s *Server) handleSubmitEnrollment(w http.ResponseWriter, r *http.Request) {
	var req brokerproto.EnrollPush
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "tx and envelope are required")
		return
	}
	account := pqcrypto.UUID(r.PathValue("id"))
	requestID := pqcrypto.UUID(r.PathValue("request"))
	op, err := pqcrypto.RequestOpID(requestID, 0)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	holder, version, err := s.store.Vault().Lock(r.Context(), string(account))
	if err != nil || holder != string(op) {
		s.writeError(w, http.StatusConflict, "no reservation for this request")
		return
	}
	var env pqcrypto.SecretEnvelope
	if _, err := canonical.Decode(req.Envelope, &env); err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "malformed envelope")
		return
	}
	ed, err := pqcrypto.ObjDigest(&env)
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "malformed envelope")
		return
	}
	var broker pqcrypto.UUID
	var tx *pqcrypto.AccessTransaction
	var v *pqcrypto.VerifiedEnvelope
	err = s.trust.View(r.Context(), func(tr *pqcrypto.Trust) error {
		if broker, err = activeBroker(tr, account); err != nil {
			return err
		}
		if tx, _, err = tr.VerifyTx(req.Tx, pqcrypto.TxContext{BrokerID: broker, Now: time.Now().UTC(), Seen: func(pqcrypto.UUID) bool { return false },
			HighestVersion: pqcrypto.Counter(version - 1), CandidateDigest: ed.Hex(), CandidateVersion: pqcrypto.Counter(version)}); err != nil {
			return err
		}
		if tx.Action.ActionType != pqcrypto.ActionEnroll || tx.RequestID != requestID || tx.Scope.ID != account {
			return pqcrypto.ErrNotAllowed
		}
		if v, err = tr.VerifyEnvelope(req.Envelope, pqcrypto.EnvelopeContext{New: true, Enroll: tx}); err != nil {
			return err
		}
		if v.RotationEnvelope() || v.Scope != tx.Scope || v.Signer != tx.RequesterPrincipalID {
			return pqcrypto.ErrNoEnroll // only the requester's user-signed candidate for this account
		}
		return nil
	})
	var perr pqcrypto.Error
	if errors.As(err, &perr) {
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "enrollment refused", "code": string(perr)})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusUnprocessableEntity, "enrollment refused")
		return
	}
	txd, _ := pqcrypto.ObjDigest(tx)
	vs := s.store.Vault()
	if err := vs.PutEnvelope(r.Context(), string(op), &store.StoredEnvelope{EnvelopeID: string(v.EnvelopeID), AccountID: string(account), SecretVersion: version,
		EnvelopeKind: v.EnvelopeKind, Digest: string(v.Digest.Hex()), Envelope: req.Envelope}); err != nil {
		s.writeError(w, http.StatusConflict, "the reservation changed")
		return
	}
	if err := vs.PutTx(r.Context(), string(requestID), string(account), tx.Action.ActionType, string(txd.Hex()), req.Tx); err != nil {
		s.writeError(w, http.StatusConflict, "a different transaction holds this request id")
		return
	}
	body, _ := json.Marshal(req)
	if err := s.relay(r.Context(), broker, brokerproto.Message{V: 1, Type: brokerproto.MsgEnroll, Body: body}, tx.ExpiresAt.Time); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "could not relay to the broker; submit again")
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]string{"state": "relayed"})
}

// handleEnrollmentStatus reports reserved, accepted, committed, failed or expired.
func (s *Server) handleEnrollmentStatus(w http.ResponseWriter, r *http.Request) {
	account := r.PathValue("id")
	op, err := pqcrypto.RequestOpID(pqcrypto.UUID(r.PathValue("request")), 0)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid request id")
		return
	}
	state, err := s.store.Vault().EnrollmentState(r.Context(), account, string(op))
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the enrollment")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"state": state})
}

var errNoPolicy = errors.New("no managed policy")

// enrollerSigned accepts a reservation only if it is recent, for this deployment and
// account, from a principal in the current policy's enroller_principal_ids, and signed by an
// active key of that principal's verified enrollment.
func enrollerSigned(tr *pqcrypto.Trust, req *brokerproto.EnrollReservation, account pqcrypto.UUID, now time.Time) error {
	p, _ := tr.Policy(account)
	if p == nil || req.AccountID != account || req.DeploymentID != tr.DeploymentID() {
		return pqcrypto.ErrNotAllowed
	}
	if d := now.Sub(req.IssuedAt.Time); d > brokerproto.ReservationMaxSkew || d < -brokerproto.ReservationMaxSkew {
		return pqcrypto.ErrExpired
	}
	allowed := false
	for _, id := range p.EnrollerPrincipalIDs {
		allowed = allowed || id == req.PrincipalID
	}
	ke := tr.Enrollment(req.PrincipalID)
	if !allowed || ke == nil {
		return pqcrypto.ErrNotAllowed
	}
	d, err := req.Digest()
	if err != nil {
		return err
	}
	for _, k := range ke.Keys {
		if k.Status == pqcrypto.StatusActive && k.SigKeyID == req.SigKeyID {
			return k.SigPub.Verify(d, req.Sig)
		}
	}
	return pqcrypto.ErrUnknownKey
}
