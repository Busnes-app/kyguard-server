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

func (s *Server) txRoutes() {
	// TODO(hawthorn §7.5): classify + step-up.
	s.mux.HandleFunc("POST /api/accounts/{id}/transactions", s.requireAuthenticated(s.handleSubmitTx))
	// TODO(hawthorn §7.5): classify.
	s.mux.HandleFunc("GET /api/transactions/{request}", s.requireAuthenticated(s.handleTxMailbox))
	// TODO(hawthorn §7.5): classify.
	s.mux.HandleFunc("POST /api/transactions/{request}/proof", s.requireAuthenticated(s.handleTxProof))
	// TODO(hawthorn §7.5): classify.
	s.mux.HandleFunc("POST /api/transactions/{request}/checkin", s.requireAuthenticated(s.handleTxCheckin))
}

// relayTx pushes one message to the account's active broker, through any replica
// (decision 75). A queued relay that no replica delivers within ten minutes is dropped.
func (s *Server) relayTx(r *http.Request, account pqcrypto.UUID, typ string, body any) error {
	var broker pqcrypto.UUID
	if err := s.trust.View(r.Context(), func(tr *pqcrypto.Trust) (err error) {
		broker, err = activeBroker(tr, account)
		return err
	}); err != nil {
		return err
	}
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	return s.relay(r.Context(), broker, brokerproto.Message{V: 1, Type: typ, Body: b}, time.Now().Add(10*time.Minute))
}

// handleSubmitTx stores a vault_checkout, standing_release or manual_rotation and relays it.
// The Control Plane checks the signatures and policy it can; the broker decides.
func (s *Server) handleSubmitTx(w http.ResponseWriter, r *http.Request) {
	var req brokerproto.TxPush
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil {
		s.writeError(w, http.StatusBadRequest, "tx is required")
		return
	}
	account := pqcrypto.UUID(r.PathValue("id"))
	var tx pqcrypto.AccessTransaction
	if _, err := canonical.Decode(req.Tx, &tx); err != nil || tx.Scope.ID != account {
		s.writeError(w, http.StatusUnprocessableEntity, "malformed transaction")
		return
	}
	switch tx.Action.ActionType {
	case pqcrypto.ActionVaultCheckout, pqcrypto.ActionStandingRelease, pqcrypto.ActionManualRotation:
	default:
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "transaction refused", "code": string(pqcrypto.ErrAction)})
		return
	}
	err := s.trust.View(r.Context(), func(tr *pqcrypto.Trust) error {
		broker, err := activeBroker(tr, account)
		if err != nil {
			return err
		}
		// Signatures, approvals, policy and validity. The current-envelope fields are the
		// broker's to check against its journal; here they are taken as given.
		_, _, err = tr.VerifyTx(req.Tx, pqcrypto.TxContext{BrokerID: broker, Now: time.Now().UTC(), Seen: func(pqcrypto.UUID) bool { return false },
			Current: &pqcrypto.CurrentEnvelope{EnvelopeID: tx.Action.EnvelopeID, SecretVersion: tx.Action.SecretVersion, ReceiptHead: tx.Action.ReceiptHeadHash}})
		return err
	})
	var perr pqcrypto.Error
	if errors.As(err, &perr) {
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "transaction refused", "code": string(perr)})
		return
	}
	if err != nil {
		s.writeError(w, http.StatusConflict, "the account has no managed policy with an active broker")
		return
	}
	d, _ := pqcrypto.ObjDigest(&tx)
	if err := s.store.Vault().PutTx(r.Context(), string(tx.RequestID), string(account), tx.Action.ActionType, string(d.Hex()), req.Tx); errors.Is(err, store.ErrConflict) {
		s.writeError(w, http.StatusConflict, "a different transaction holds this request id")
		return
	} else if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not store the transaction")
		return
	}
	if err := s.store.Audit().LogAudit(r.Context(), &store.AuditRecord{UserID: s.actor(r), Action: "vault.transaction_relayed", Resource: "account:" + string(account),
		Details: "action=" + tx.Action.ActionType + " request_id=" + string(tx.RequestID), IPAddress: s.requestIP(r)}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not audit")
		return
	}
	if err := s.relayTx(r, account, brokerproto.MsgTx, req); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "the broker is not connected; submit again")
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]string{"state": "relayed"})
}

func (s *Server) handleTxMailbox(w http.ResponseWriter, r *http.Request) {
	m, err := s.store.Vault().TxMailbox(r.Context(), r.PathValue("request"))
	if errors.Is(err, store.ErrNotFound) {
		s.writeError(w, http.StatusNotFound, "unknown transaction")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read the transaction")
		return
	}
	out := map[string]any{"challenge": m.Challenge, "purpose": m.Purpose, "result": m.Result}
	if m.Delivery != "" {
		out["delivery"] = json.RawMessage(m.Delivery)
	}
	s.writeJSON(w, http.StatusOK, out)
}

func (s *Server) txOf(r *http.Request) (pqcrypto.UUID, pqcrypto.UUID, bool) {
	id := pqcrypto.UUID(r.PathValue("request"))
	acct, err := s.store.Vault().TxAccount(r.Context(), string(id))
	return id, pqcrypto.UUID(acct), err == nil
}

func (s *Server) handleTxProof(w http.ResponseWriter, r *http.Request) {
	id, acct, ok := s.txOf(r)
	if !ok {
		s.writeError(w, http.StatusNotFound, "unknown transaction")
		return
	}
	var req struct {
		Proof pqcrypto.B64 `json:"proof"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBody)).Decode(&req); err != nil || len(req.Proof) == 0 {
		s.writeError(w, http.StatusBadRequest, "proof is required")
		return
	}
	if err := s.relayTx(r, acct, brokerproto.MsgProof, brokerproto.ProofPush{RequestID: id, Proof: req.Proof}); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "the broker is not connected; submit again")
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]string{"state": "relayed"})
}

func (s *Server) handleTxCheckin(w http.ResponseWriter, r *http.Request) {
	id, acct, ok := s.txOf(r)
	if !ok {
		s.writeError(w, http.StatusNotFound, "unknown transaction")
		return
	}
	if err := s.relayTx(r, acct, brokerproto.MsgCheckin, brokerproto.CheckinPush{RequestID: id}); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "the broker is not connected; submit again")
		return
	}
	s.writeJSON(w, http.StatusAccepted, map[string]string{"state": "relayed"})
}
