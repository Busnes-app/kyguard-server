package brokerproto

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// BrokerVersion is the version this build's broker announces.
const BrokerVersion = "0.1.0"

const maxPairBody = 64 << 10

// Listener serves /broker/v1/* on its own TLS listener (§4.1). It is never mounted on the
// main mux.
type Listener struct {
	Store      store.Store
	Trust      *cptrust.Trust
	CA         *CA
	MinVersion string
	Now        func() time.Time

	mu    sync.Mutex
	conns map[pqcrypto.UUID]*websocket.Conn
}

// Handler returns the listener's routes; everything else is 404.
func (l *Listener) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+PathPair, l.handlePair)
	mux.HandleFunc("GET "+PathChannel, l.handleChannel)
	return mux
}

func (l *Listener) now() time.Time {
	if l.Now != nil {
		return l.Now().UTC()
	}
	return time.Now().UTC()
}

// HashSecret is how pairing token secrets are stored.
func HashSecret(secret []byte) string {
	s := sha256.Sum256(secret)
	return hex.EncodeToString(s[:])
}

// NewBrokerID returns a random 128-bit broker_id in UUID form (§4.1 pairing step 3).
func NewBrokerID() pqcrypto.UUID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return pqcrypto.UUID(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

func (l *Listener) handlePair(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPairBody))
	if err != nil {
		http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
		return
	}
	var req PairRequest
	if _, err := canonical.Decode(body, &req); err != nil || len(req.Secret) != 32 || len(req.EncPub) != recoverykey.PublicKeyBytes || req.Version == "" {
		http.Error(w, "malformed pairing request", http.StatusBadRequest)
		return
	}
	sigKeyID, err := req.SigPub.SigKeyID()
	if err != nil {
		http.Error(w, "malformed pairing request", http.StatusBadRequest)
		return
	}
	encKeyID, err := pqcrypto.EncKeyID(req.EncPub)
	if err != nil {
		http.Error(w, "malformed pairing request", http.StatusBadRequest)
		return
	}
	var bundle *store.BootstrapBundle
	if bundle, err = l.Store.Guard().Bundle(r.Context()); err != nil {
		http.Error(w, "deployment not initialized", http.StatusServiceUnavailable)
		return
	}
	id := NewBrokerID()
	cert, err := l.CA.IssueBroker(req.CSR, id)
	if err != nil {
		http.Error(w, "invalid certificate request", http.StatusBadRequest)
		return
	}
	b := &store.Broker{ID: string(id), CertSHA256: string(CertSHA256(cert)), CASHA256: string(l.CA.SHA256()),
		SigKeyID: string(sigKeyID), EncKeyID: string(encKeyID), Version: req.Version}
	intent := uuid.NewString()
	err = l.Store.Guard().ClaimPairing(r.Context(), HashSecret(req.Secret), l.now(), b, intent,
		&store.AuditRecord{UserID: "broker:" + b.ID, Action: "broker.paired", Resource: "broker:" + b.ID,
			Details: "sig_key_id=" + b.SigKeyID + " enc_key_id=" + b.EncKeyID + " cert_sha256=" + b.CertSHA256, IPAddress: r.RemoteAddr})
	if errors.Is(err, store.ErrNotFound) {
		http.Error(w, "invalid or expired pairing token", http.StatusForbidden)
		return
	}
	if err != nil {
		log.Printf("[BROKER] pairing claim failed: %v", err)
		http.Error(w, "pairing failed", http.StatusInternalServerError)
		return
	}
	// The token is consumed. From here a lost response leaves the intent for an operator
	// (§9.3): it ends complete only if the response was written in full.
	resp, err := canonical.Marshal(PairResponse{BrokerID: id, Cert: cert, CACert: l.CA.Cert.Raw, Bundle: bundle.Bundle})
	state := store.IntentOutcomeUnknown
	if err == nil {
		w.Header().Set("Content-Type", "application/json")
		_, err = w.Write(resp)
		if err == nil {
			err = http.NewResponseController(w).Flush()
		}
		if err == nil {
			state = store.IntentComplete
		}
	}
	ctx := context.WithoutCancel(r.Context())
	if serr := l.Store.Guard().SetIntentState(ctx, intent, store.IntentPending, state); serr != nil {
		log.Printf("[BROKER] pairing intent %s: %v", intent, serr)
		return
	}
	if state != store.IntentComplete {
		log.Printf("[BROKER] pairing response for broker %s was not delivered: intent %s is outcome_unknown", id, intent)
		if aerr := l.Store.Audit().LogAudit(ctx, &store.AuditRecord{UserID: "system", Action: "pairing.outcome_unknown", Resource: "operation:" + intent, Details: "subject=" + string(id)}); aerr != nil {
			log.Printf("[BROKER] pairing intent %s: audit: %v", intent, aerr)
		}
	}
}

// Admit checks a channel client: a verified internal-CA certificate whose broker_id is an
// active member of its pool's current manifest with that exact certificate hash (§4.1).
func (l *Listener) Admit(ctx context.Context, r *http.Request) (*store.Broker, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("client certificate required")
	}
	leaf := r.TLS.PeerCertificates[0]
	id, err := BrokerIDOf(leaf)
	if err != nil {
		return nil, err
	}
	sha := CertSHA256(leaf.Raw)
	b, err := l.Store.Guard().GetBroker(ctx, string(id))
	if err != nil {
		return nil, errors.New("unknown broker")
	}
	err = l.Trust.View(ctx, func(tr *pqcrypto.Trust) error {
		pool := tr.Pool(pqcrypto.UUID(b.PoolID))
		if pool == nil {
			return errors.New("no pool manifest for the broker's pool")
		}
		m := pool.Member(id)
		if m == nil || m.Status != pqcrypto.StatusActive || m.MTLSCertSHA256 != sha {
			return errors.New("broker is not an active member of its pool manifest")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return b, nil
}

func (l *Listener) handleChannel(w http.ResponseWriter, r *http.Request) {
	b, err := l.Admit(r.Context(), r)
	if err != nil {
		log.Printf("[BROKER] channel refused from %s: %v", r.RemoteAddr, err)
		http.Error(w, "broker not admitted", http.StatusForbidden)
		return
	}
	if v := r.Header.Get(VersionHeader); !VersionAtLeast(v, l.MinVersion) {
		http.Error(w, "broker version below min_broker_version", http.StatusUpgradeRequired)
		return
	}
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(1 << 20)
	id := pqcrypto.UUID(b.ID)
	l.mu.Lock()
	if l.conns == nil {
		l.conns = map[pqcrypto.UUID]*websocket.Conn{}
	}
	old := l.conns[id]
	l.conns[id] = c
	l.mu.Unlock()
	if old != nil {
		// Close waits up to 5s for the peer's close frame; never under l.mu.
		go old.Close(websocket.StatusPolicyViolation, "replaced by a newer connection")
	}
	defer func() {
		l.mu.Lock()
		if l.conns[id] == c {
			delete(l.conns, id)
		}
		l.mu.Unlock()
		c.CloseNow()
	}()
	for {
		_, data, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var m Message
		if err := json.Unmarshal(data, &m); err != nil || m.V != 1 || m.ID == 0 {
			c.Close(websocket.StatusUnsupportedData, "unsupported message")
			return
		}
		res := Message{V: 1, Type: MsgResult, ID: m.ID}
		out, err := l.handle(r.Context(), b, m)
		if err == nil && out != nil {
			res.Body, err = json.Marshal(out)
		}
		if err != nil {
			res.Body, res.Error = nil, refusal(err)
		}
		reply, _ := json.Marshal(res)
		if err := c.Write(r.Context(), websocket.MessageText, reply); err != nil {
			return
		}
	}
}

// Send writes one message to a connected broker.
func (l *Listener) Send(ctx context.Context, broker pqcrypto.UUID, m Message) error {
	l.mu.Lock()
	c := l.conns[broker]
	l.mu.Unlock()
	if c == nil {
		return errors.New("broker not connected")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	return c.Write(ctx, websocket.MessageText, b)
}

// VersionAtLeast compares dotted numeric versions; anything unparsable is below every
// minimum.
func VersionAtLeast(v, minimum string) bool {
	a, ok1 := parseVersion(v)
	b, ok2 := parseVersion(minimum)
	if !ok1 || !ok2 {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

func parseVersion(s string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || strconv.Itoa(n) != p {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// refusal is what the broker is told: stable codes for the refusals it acts on, a generic
// word for internal failures.
func refusal(err error) string {
	var perr pqcrypto.Error
	switch {
	case errors.Is(err, store.ErrLocked):
		return "locked"
	case errors.Is(err, store.ErrConflict):
		return "conflict"
	case errors.As(err, &perr):
		return string(perr)
	case errors.Is(err, errNotActive), errors.Is(err, errNotInPool), errors.Is(err, errNotSigner),
		errors.Is(err, errOperation), errors.Is(err, errUnsupported):
		return err.Error()
	}
	log.Printf("[BROKER] channel request failed: %v", err)
	return "internal error"
}
