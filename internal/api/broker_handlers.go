package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// PairingTokenTTL is the lifetime of a broker pairing token (§4.1 pairing step 1).
const PairingTokenTTL = 10 * time.Minute

func (s *Server) brokerRoutes() {
	// Broker and pairing actions need a step-up in the last five minutes (spec §7.3 rule 6).
	s.route(ClassSession, "POST /api/broker-pools", http.HandlerFunc(s.requireAdmin(s.handleCreatePool)), fresh(StepupWindow))
	s.route(ClassSession, "POST /api/broker-pools/{id}/pairing-tokens", http.HandlerFunc(s.requireAdmin(s.handleCreatePairingToken)), fresh(StepupWindow))
	// Manifests carry their own Custodian signatures; the session only rate-limits callers.
	s.route(ClassSession, "POST /api/manifests", http.HandlerFunc(s.handleSubmitManifest))
}

func (s *Server) actor(r *http.Request) string {
	if u, _, err := s.sessions.AuthenticateRequest(r); err == nil {
		return u.ID
	}
	return ""
}

func (s *Server) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" || len(req.Name) > 128 {
		s.writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	id, err := uuid.NewV7()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not create pool")
		return
	}
	p := &store.BrokerPool{ID: id.String(), Name: strings.TrimSpace(req.Name), CreatedAt: time.Now().UTC()}
	err = s.store.Guard().CreatePool(r.Context(), p, &store.AuditRecord{UserID: s.actor(r), Action: "broker.pool_created", Resource: "pool:" + p.ID, Details: "name=" + p.Name, IPAddress: s.requestIP(r)})
	if errors.Is(err, store.ErrAlreadyExists) {
		s.writeError(w, http.StatusConflict, "a pool with that name exists")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not create pool")
		return
	}
	s.writeJSON(w, http.StatusCreated, p)
}

func (s *Server) handleCreatePairingToken(w http.ResponseWriter, r *http.Request) {
	if s.config.Broker.Hostname == "" || s.brokerCA == nil {
		s.writeError(w, http.StatusServiceUnavailable, "broker listener is not configured (KY_BROKER_HOSTNAME, kyguard-server init)")
		return
	}
	if _, err := s.store.Guard().Bundle(r.Context()); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "import the bootstrap bundle first (kyguard-server import-bundle)")
		return
	}
	pool, err := s.store.Guard().GetPool(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeError(w, http.StatusNotFound, "pool not found")
		return
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	tok, err := brokerproto.Token{CASHA256: s.brokerCA.SHA256(), Secret: secret, URL: s.config.Broker.URL()}.Encode()
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	now := time.Now().UTC()
	t := &store.PairingToken{TokenHash: brokerproto.HashSecret(secret), PoolID: pool.ID, CreatedBy: s.actor(r), CreatedAt: now, ExpiresAt: now.Add(PairingTokenTTL)}
	if err := s.store.Guard().CreatePairingToken(r.Context(), t, &store.AuditRecord{UserID: t.CreatedBy, Action: "broker.pairing_token_created", Resource: "pool:" + pool.ID, IPAddress: s.requestIP(r)}); err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not create token")
		return
	}
	s.writeJSON(w, http.StatusCreated, map[string]any{"token": tok, "expires_at": t.ExpiresAt})
}

func (s *Server) handleSubmitManifest(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, cptrust.MaxManifest))
	if err != nil {
		s.writeError(w, http.StatusRequestEntityTooLarge, "manifest too large")
		return
	}
	rec, added, err := s.trust.Submit(r.Context(), raw, s.actor(r), s.requestIP(r))
	var perr pqcrypto.Error
	switch {
	case errors.Is(err, cptrust.ErrNoBundle):
		s.writeError(w, http.StatusServiceUnavailable, "import the bootstrap bundle first")
		return
	case errors.Is(err, store.ErrLeaseOpen):
		s.writeError(w, http.StatusConflict, "a checkout lease is open for this account; submit this policy after its cleanup closes it")
		return
	case errors.As(err, &perr):
		s.writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "manifest refused", "code": string(perr)})
		return
	case err != nil:
		log.Printf("[TRUST] manifest submission failed: %v", err)
		s.writeError(w, http.StatusUnprocessableEntity, "manifest refused")
		return
	}
	status := http.StatusCreated
	if !added {
		status = http.StatusOK
	}
	s.writeJSON(w, status, map[string]string{"type": rec.Type, "scope_id": string(rec.ScopeID), "epoch": rec.Epoch.String(), "digest": string(rec.Digest.Hex())})
}
