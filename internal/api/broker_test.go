package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

func setupBrokerServer(t *testing.T) (*api.Server, store.Store, *brokerproto.CA, *pqtest.Deployment) {
	t.Helper()
	dir := t.TempDir()
	ca, err := brokerproto.CreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KY_DATA_DIR", dir)
	t.Setenv("KY_BROKER_HOSTNAME", "broker.example.test")
	t.Setenv("KY_BROKER_LISTEN", ":9443")
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = testdb.Config(t)
	cfg.Database.DataDir = dir
	cfg.Captcha.Provider = "none"
	st, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := pqtest.New(t)
	if err := st.Guard().ImportBundle(context.Background(), &store.BootstrapBundle{DeploymentID: string(d.ID), Fingerprint: string(d.Fingerprint), Bundle: d.Bundle}, "host"); err != nil {
		t.Fatal(err)
	}
	return api.NewServer(cfg, st), st, ca, d
}

func postJSON(srv *api.Server, session *http.Cookie, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, bytes.NewReader(body))
	if session != nil {
		req.AddCookie(session)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
		req.Header.Set(auth.HeaderCSRF, "test-csrf")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func TestPairingTokensNeedAnAdminAndPinTheCA(t *testing.T) {
	srv, st, ca, _ := setupBrokerServer(t)
	admin := loginAs(t, srv, st, "admin1", "admin")
	user := loginAs(t, srv, st, "user1", "user")

	if w := postJSON(srv, user, "/api/broker-pools", []byte(`{"name":"dc1"}`)); w.Code != http.StatusForbidden {
		t.Fatalf("user created a pool: %d", w.Code)
	}
	w := postJSON(srv, admin, "/api/broker-pools", []byte(`{"name":"dc1"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("create pool: %d %s", w.Code, w.Body)
	}
	var pool store.BrokerPool
	json.Unmarshal(w.Body.Bytes(), &pool)

	path := "/api/broker-pools/" + pool.ID + "/pairing-tokens"
	if w := postJSON(srv, nil, path, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous token: %d", w.Code)
	}
	if w := postJSON(srv, user, path, nil); w.Code != http.StatusForbidden {
		t.Fatalf("user token: %d", w.Code)
	}
	w = postJSON(srv, admin, path, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("token: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	json.Unmarshal(w.Body.Bytes(), &resp)
	tok, err := brokerproto.ParseToken(resp.Token)
	if err != nil {
		t.Fatal(err)
	}
	if tok.CASHA256 != ca.SHA256() || tok.URL != "https://broker.example.test:9443" {
		t.Fatalf("token %+v", tok)
	}
	if d := time.Until(resp.ExpiresAt); d > 10*time.Minute || d < 9*time.Minute {
		t.Fatalf("ttl %v", d)
	}
	// Stored hashed: the secret itself is nowhere in the store.
	now := time.Now().UTC()
	if err := st.Guard().ClaimPairing(context.Background(), string(tok.Secret), now, &store.Broker{ID: "x", CertSHA256: "c", CASHA256: "a", SigKeyID: "s", EncKeyID: "e", Version: "0.1.0"}, "i", nil); err == nil {
		t.Fatal("the raw secret matched a stored token")
	}
	if w := postJSON(srv, admin, "/api/broker-pools/"+string(pqtest.UUID())+"/pairing-tokens", nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown pool: %d", w.Code)
	}
}

func TestSubmitManifestVerifiesSignatures(t *testing.T) {
	srv, st, _, d := setupBrokerServer(t)
	user := loginAs(t, srv, st, "custodian1", "user")
	raw := d.Pool(t, pqtest.UUID(), 1, []pqcrypto.BrokerMember{}, nil)
	if w := postJSON(srv, nil, "/api/manifests", raw); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	if w := postJSON(srv, user, "/api/manifests", raw); w.Code != http.StatusCreated {
		t.Fatalf("submit: %d %s", w.Code, w.Body)
	}
	if w := postJSON(srv, user, "/api/manifests", raw); w.Code != http.StatusOK {
		t.Fatalf("resubmit: %d %s", w.Code, w.Body)
	}
	forged := pqtest.New(t).Pool(t, pqtest.UUID(), 1, []pqcrypto.BrokerMember{}, nil)
	w := postJSON(srv, user, "/api/manifests", forged)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("foreign custodians: %d %s", w.Code, w.Body)
	}
}

// §3.8: an epoch at 2^63-1 is stored and read back intact; one above it is refused at
// decode, so a manifest epoch never reaches the BIGINT column out of range.
func TestSubmitManifestEpochAtTheCounterLimit(t *testing.T) {
	srv, st, _, d := setupBrokerServer(t)
	user := loginAs(t, srv, st, "custodian1", "user")
	raw := d.Pool(t, pqtest.UUID(), pqcrypto.MaxCounter, []pqcrypto.BrokerMember{}, nil)
	w := postJSON(srv, user, "/api/manifests", raw)
	if w.Code != http.StatusCreated || !strings.Contains(w.Body.String(), `"epoch":"9223372036854775807"`) {
		t.Fatalf("max epoch: %d %s", w.Code, w.Body)
	}
	ms, err := st.Guard().Manifests(context.Background(), 0)
	if err != nil || len(ms) != 1 || ms[0].Epoch != pqcrypto.MaxCounter {
		t.Fatalf("stored: %+v %v", ms, err)
	}
	over := bytes.Replace(raw, []byte(`"9223372036854775807"`), []byte(`"9223372036854775808"`), 1)
	if bytes.Equal(over, raw) {
		t.Fatal("epoch not found in manifest")
	}
	w = postJSON(srv, user, "/api/manifests", over)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), `"code":"invalid_counter"`) {
		t.Fatalf("epoch above 2^63-1: %d %s", w.Code, w.Body)
	}
	if ms, _ := st.Guard().Manifests(context.Background(), 0); len(ms) != 1 {
		t.Fatalf("over-limit manifest stored: %d rows", len(ms))
	}
}
