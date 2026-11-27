package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/xwing"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/vaultclient"
)

func TestEncryptedBrowserKeyBelongsToItsSSOAccount(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Server.BrowserVault = true
	srv := api.NewServer(cfg, st)
	d := pqtest.New(t)
	ctx := context.Background()
	if err := st.Guard().ImportBundle(ctx, &store.BootstrapBundle{
		DeploymentID: string(d.ID), Fingerprint: string(d.Fingerprint), Bundle: d.Bundle,
		ImportedAt: time.Now().UTC(),
	}, ""); err != nil {
		t.Fatal(err)
	}
	user := func(id string, stale bool) string {
		t.Helper()
		issuer := "https://identity.example.test"
		u := &store.User{ID: id, Username: id, Role: "user", Status: "active", AccountType: store.AccountSSO,
			SSOProvider: "oidc", SSOIssuer: issuer, SSOSubject: id}
		if err := st.Users().CreateUser(ctx, u); err != nil {
			t.Fatal(err)
		}
		now := time.Now().UTC()
		stepup := now
		if stale {
			stepup = now.Add(-6 * time.Minute)
		}
		token := crypto.RandomHex(32)
		if err := st.Sessions().CreateSession(ctx, &store.Session{UserID: u.ID, TokenHash: crypto.SHA256Hex([]byte(token)),
			SSOIssuer: issuer, Stage: store.StageActive, StepupAt: &stepup, CreatedAt: now, ExpiresAt: now.Add(time.Hour)}, ""); err != nil {
			t.Fatal(err)
		}
		return token
	}
	alice, bob, stale := user("alice", false), user("bob", false), user("carol", true)
	call := func(method, token string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, "/api/user/vault-key", bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	upload := func(subject string) ([]byte, *pqcrypto.KeyEnrollmentManifest) {
		t.Helper()
		k, m, err := vaultclient.CreateKey(d.ID, "https://identity.example.test", subject)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := vaultclient.SealKey(k, m, vaultclient.Passphrase, "", 0, []byte("vault test passphrase"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := json.Marshal(map[string]any{"sealed": sealed, "enrollment": pqcrypto.B64(pqtest.Canon(t, m))})
		if err != nil {
			t.Fatal(err)
		}
		return b, m
	}
	body, draft := upload("alice")
	if w := call("PUT", bob, body); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("another identity could store Alice's enrollment: %d %s", w.Code, w.Body)
	}
	if w := call("PUT", stale, body); w.Code != http.StatusForbidden {
		t.Fatalf("stale step-up accepted: %d %s", w.Code, w.Body)
	}
	for range 2 {
		if w := call("PUT", alice, body); w.Code != http.StatusNoContent {
			t.Fatalf("store or retry: %d %s", w.Code, w.Body)
		}
	}
	if body, _ := upload("alice"); call("PUT", alice, body).Code != http.StatusConflict {
		t.Fatal("a second upload replaced the enrolled key")
	}
	if w := call("GET", alice, nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"sealed":`) ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("stored key was unavailable: %d %s", w.Code, w.Body)
	}
	if w := call("GET", bob, nil); w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"sealed":`) {
		t.Fatalf("another user could read the stored key: %d %s", w.Code, w.Body)
	}
	if w := call("GET", "", nil); w.Code != http.StatusUnauthorized {
		t.Fatal("anonymous client read the key")
	}
	if w := postJSON(srv, nil, "/api/manifests", pqtest.Canon(t, draft)); w.Code != http.StatusUnauthorized {
		t.Fatal("signed draft bypassed the API session requirement")
	}
}

func TestBrowserVaultIncludesPoolsNamedByHistoricalPolicies(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	cfg.Server.BrowserVault = true
	srv := api.NewServer(cfg, st)
	ctx := context.Background()
	now := time.Now().UTC()
	d := pqtest.New(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Guard().ImportBundle(ctx, &store.BootstrapBundle{
		DeploymentID: string(d.ID), Fingerprint: string(d.Fingerprint), Bundle: d.Bundle, ImportedAt: now,
	}, ""))
	principal := pqtest.NewPrincipal(t)
	u := &store.User{ID: "alice", Username: "alice", Role: "user", Status: "active", AccountType: store.AccountSSO,
		SSOProvider: "oidc", SSOIssuer: "https://idp.example.test", SSOSubject: "sub-" + string(principal.ID)}
	must(st.Users().CreateUser(ctx, u))
	token := crypto.RandomHex(32)
	must(st.Sessions().CreateSession(ctx, &store.Session{
		UserID: u.ID, TokenHash: crypto.SHA256Hex([]byte(token)), SSOIssuer: u.SSOIssuer,
		Stage: store.StageActive, StepupAt: &now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}, ""))
	request := func(method, path string, body []byte) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	submit := func(raw []byte) {
		t.Helper()
		if w := request("POST", "/api/manifests", raw); w.Code != http.StatusCreated {
			t.Fatalf("manifest: %d %s", w.Code, w.Body)
		}
	}
	before, after, other := pqtest.UUID(), pqtest.UUID(), pqtest.UUID()
	account, asset := pqtest.UUID(), pqtest.UUID()
	must(st.Guard().CreatePool(ctx, &store.BrokerPool{ID: string(before), Name: "old", CreatedAt: now}, nil))
	must(st.Vault().CreateAsset(ctx, &store.Asset{ID: string(asset), Name: "host"}))
	must(st.Vault().CreateAccount(ctx, &store.Account{ID: string(account), AssetID: string(asset), Name: "svc",
		AccountKind: pqcrypto.KindManaged, PoolID: string(before)}))
	target, digest := d.SSHTarget(t, account, asset, "host.example.test", 22, "svc", pqcrypto.HexID(strings.Repeat("ab", 32)))
	must(st.Vault().PutTargetDescriptor(ctx, string(digest), string(account), target))
	submit(d.Enrollment(t, principal, 1))
	for _, id := range []pqcrypto.UUID{before, after, other} {
		submit(d.Pool(t, id, 1, []pqcrypto.BrokerMember{}, nil))
	}
	for i, id := range []pqcrypto.UUID{before, after} {
		policy := d.ManagedPolicy(account, id, pqcrypto.Counter(i+1), digest)
		policy.AllowedUserPrincipalIDs = []pqcrypto.UUID{principal.ID}
		submit(d.Signed(t, policy))
	}

	w := request("GET", "/api/accounts/"+string(account)+"/vault-context", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("context: %d %s", w.Code, w.Body)
	}
	var out struct{ Manifests []pqcrypto.B64 }
	must(json.Unmarshal(w.Body.Bytes(), &out))
	tr := d.Trust(t)
	for _, raw := range out.Manifests {
		_, err := tr.Accept(raw)
		must(err)
	}
	if tr.Lookup(pqcrypto.TypePool, before) == nil || tr.Lookup(pqcrypto.TypePool, after) == nil ||
		tr.Lookup(pqcrypto.TypePool, other) != nil {
		t.Fatal("browser context must include only the pools referenced by this account's policies")
	}
}

func TestKeyringExchangePreservesOIDCChecksAndIssuesPendingSession(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	f := newFakeKySignOn(t)
	cfg.Server.BrowserVault, cfg.Server.AppURL = true, "https://guard.example.test"
	cfg.SSO.Enabled, cfg.SSO.AutoProvision = true, true
	cfg.SSO.KySignOnIssuer, cfg.SSO.KySignOnClientID, cfg.SSO.KySignOnKeyringOrg = f.issuer, "client", "org-A"
	srv := api.NewServer(cfg, st)
	pair, err := xwing.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pk := pqcrypto.EncodeB64(pair.Public().Bytes())
	start := func() (map[string]string, []*http.Cookie) {
		t.Helper()
		raw, _ := json.Marshal(map[string]string{"keyring_pk": pk})
		req := httptest.NewRequest("POST", "https://guard.example.test/api/sso/kysignon/keyring/start", bytes.NewReader(raw))
		req.Header.Set("Origin", cfg.Server.AppURL)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		var out map[string]string
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil {
			t.Fatalf("start: %d %s", w.Code, w.Body)
		}
		authURL, err := url.Parse(out["authorization_url"])
		if err != nil {
			t.Fatal(err)
		}
		q := authURL.Query()
		if q.Get("keyring_pk") != pk || q.Get("code_challenge_method") != "S256" ||
			q.Get("redirect_uri") != cfg.Server.AppURL+"/vault/keyring-callback" || q.Get("nonce") != out["nonce"] ||
			q.Get("state") != out["state"] || q.Get("max_age") != "0" {
			t.Fatal("authorization request omitted an OAuth binding")
		}
		return out, w.Result().Cookies()
	}
	exchange := func(in map[string]string, cookies []*http.Cookie, nonce, org string) *httptest.ResponseRecorder {
		t.Helper()
		f.idToken = f.sign(t, "", map[string]any{"sub": "alice", "org_id": org, "sid": "keyring", "nonce": nonce, "auth_time": time.Now().Unix()})
		raw, _ := json.Marshal(map[string]string{"state": in["state"], "code": "auth-code"})
		r := httptest.NewRequest("POST", cfg.Server.AppURL+"/api/sso/kysignon/keyring/exchange", bytes.NewReader(raw))
		r.Header.Set("Origin", cfg.Server.AppURL)
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w
	}
	in, cookies := start()
	if w := exchange(in, cookies, "different-nonce", "org-A"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong nonce accepted: %d %s", w.Code, w.Body)
	}
	in, cookies = start()
	if w := exchange(in, cookies, in["nonce"], "org-B"); w.Code != http.StatusForbidden {
		t.Fatalf("wrong organization accepted: %d %s", w.Code, w.Body)
	}
	in, cookies = start()
	w := exchange(in, cookies, in["nonce"], "org-A")
	if w.Code != http.StatusOK || sessionCookie(w) == nil || !strings.Contains(w.Body.String(), `"subject":"alice"`) ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("exchange: %d %s", w.Code, w.Body)
	}
	req := httptest.NewRequest("GET", "/api/user/vault-key", nil)
	req.AddCookie(sessionCookie(w))
	blocked := httptest.NewRecorder()
	srv.ServeHTTP(blocked, req)
	if blocked.Code != http.StatusForbidden || !strings.Contains(blocked.Body.String(), "stepup_required") {
		t.Fatalf("a keyring login bypassed TOTP: %d %s", blocked.Code, blocked.Body)
	}
}
