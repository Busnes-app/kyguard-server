package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

const cliVerifier = "cli-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// cliCallback runs the SSO login as kyguard-cli starts it (loopback port, S256 challenge) and
// returns the callback response.
func cliCallback(t *testing.T, srv *api.Server, f *fakeKySignOn, sub, sid string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sso/kysignon/login?cli_port=41234&cli_challenge="+s256(cliVerifier), nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil {
		t.Fatalf("login redirect: %d %s", w.Code, w.Body.String())
	}
	q := loc.Query()
	claims := map[string]any{"sub": sub, "sid": sid, "nonce": q.Get("nonce"), "preferred_username": sub, "iat": time.Now().Unix(), "auth_time": time.Now().Unix()}
	for k, v := range mfaClaims {
		claims[k] = v
	}
	f.idToken = f.sign(t, "", claims)
	req := httptest.NewRequest(http.MethodGet, "/api/sso/kysignon/callback?code=c&state="+q.Get("state"), nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// cliCode is the one-time code the callback sent to the CLI's loopback listener.
func cliCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil || loc.Scheme != "http" || loc.Host != "127.0.0.1:41234" || loc.Path != "/cb" || loc.Query().Get("code") == "" {
		t.Fatalf("callback: %d to %q", w.Code, w.Header().Get("Location"))
	}
	if sessionCookie(w) != nil {
		t.Fatal("a CLI login left a session cookie in the browser")
	}
	return loc.Query().Get("code")
}

func cliExchange(srv *api.Server, code, verifier string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"code": code, "code_verifier": verifier})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/cli/exchange", bytes.NewReader(body)))
	return w
}

func bearer(srv *api.Server, token, method, path string, body any) *httptest.ResponseRecorder {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func tokenOf(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var out struct{ Token string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Token == "" {
		t.Fatalf("%d %s: no token", w.Code, w.Body)
	}
	return out.Token
}

// §7.6: the callback of a CLI login sends a one-time code to the loopback listener and sets
// no browser session. Code and verifier buy a pending session (bearer), which session routes
// refuse until TOTP step-up in the terminal returns an active token. A code is spent by its
// first attempt, even one with the wrong verifier.
func TestCLILoginHandsAPendingSessionToTheCLI(t *testing.T) {
	srv, _, f := ssoServer(t)
	code := cliCode(t, cliCallback(t, srv, f, "cli-user", "sid-1"))
	if w := cliExchange(srv, code, "wrong-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong verifier: %d %s", w.Code, w.Body)
	}
	if w := cliExchange(srv, code, cliVerifier); w.Code != http.StatusUnauthorized {
		t.Fatalf("a code spent by a wrong verifier redeemed: %d", w.Code)
	}

	pendingToken := tokenOf(t, cliExchange(srv, cliCode(t, cliCallback(t, srv, f, "cli-user", "sid-2")), cliVerifier))
	if w := bearer(srv, pendingToken, "GET", "/api/admin/users", nil); w.Code != http.StatusForbidden {
		t.Fatalf("pending CLI session on a session route: %d", w.Code)
	}
	w := bearer(srv, pendingToken, "POST", "/api/auth/stepup/enroll", nil)
	var offer struct{ Secret string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &offer) != nil {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	totpCode, _ := totp.Code(offer.Secret, time.Now())
	active := tokenOf(t, bearer(srv, pendingToken, "POST", "/api/auth/stepup/enroll/confirm", map[string]string{"code": totpCode}))
	if w := bearer(srv, active, "GET", "/api/admin/users", nil); w.Code != http.StatusOK {
		t.Fatalf("active CLI session: %d %s", w.Code, w.Body)
	}
	if w := bearer(srv, pendingToken, "GET", "/api/auth/me", nil); bytes.Contains(w.Body.Bytes(), []byte(`"authenticated":true`)) {
		t.Fatal("the pending CLI token survived its exchange")
	}
}

// §7.6: a code is valid for 60 seconds.
func TestExpiredCLICodeIsRefused(t *testing.T) {
	srv, st, f := ssoServer(t)
	cliCode(t, cliCallback(t, srv, f, "late", "sid-1")) // provisions the account
	u, err := st.Users().GetUserByUsername(context.Background(), "late")
	if err != nil {
		t.Fatal(err)
	}
	code := "expired-code"
	if err := st.Sessions().CreateCLICode(context.Background(), &store.CLICode{CodeHash: crypto.SHA256Hex([]byte(code)), UserID: u.ID, SSOIssuer: f.issuer, SSOSID: "sid-9",
		IssuedAt: time.Now(), Challenge: s256(cliVerifier), ExpiresAt: time.Now().Add(-time.Second)}, &store.AuditRecord{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if w := cliExchange(srv, code, cliVerifier); w.Code != http.StatusUnauthorized {
		t.Fatalf("expired code: %d %s", w.Code, w.Body)
	}
	if api.CLICodeTTL != 60*time.Second {
		t.Fatalf("code TTL %v", api.CLICodeTTL)
	}
}

// Acceptance 7: a back-channel logout between callback and CLI code redemption, by sid or by
// subject, makes the redemption fail.
func TestLogoutBeforeCLIRedemptionEndsTheSignIn(t *testing.T) {
	srv, _, f := ssoServer(t)
	for _, by := range []struct{ sub, sid, logoutSid string }{{"bysid", "sid-1", "sid-1"}, {"bysub", "sid-2", ""}} {
		code := cliCode(t, cliCallback(t, srv, f, by.sub, by.sid))
		time.Sleep(1100 * time.Millisecond) // the subject fence compares whole seconds of iat
		if w := postLogout(srv, f.logoutToken(t, by.sub, by.logoutSid)); w.Code != http.StatusOK {
			t.Fatalf("logout: %d %s", w.Code, w.Body)
		}
		if w := cliExchange(srv, code, cliVerifier); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s: redemption after logout: %d %s", by.sub, w.Code, w.Body)
		}
	}
}

// Acceptance 7, concurrent: a back-channel logout racing CLI code redemption never leaves a
// session behind its fence (both drivers; the spec requires PostgreSQL).
func TestLogoutRacingCLIRedemptionLeavesNoSession(t *testing.T) {
	_, st, _ := setupTestServer(t)
	ctx := context.Background()
	const issuer = "https://idp.race"
	u := &store.User{ID: "usr_clirace", Username: "clirace", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "clirace", SSOIssuer: issuer}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	iat := time.Now().UTC().Add(-time.Second)
	for i := range 25 {
		sid := fmt.Sprintf("sid-%d", i)
		code := &store.CLICode{CodeHash: "code-" + sid, UserID: u.ID, SSOIssuer: issuer, SSOSID: sid, IssuedAt: iat, Challenge: "c", ExpiresAt: time.Now().Add(time.Minute)}
		if err := st.Sessions().CreateCLICode(ctx, code, &store.AuditRecord{Action: "test"}); err != nil {
			t.Fatal(err)
		}
		sess := &store.Session{TokenHash: "cli-" + sid, UserID: u.ID, CreatedAt: iat, ExpiresAt: time.Now().Add(time.Minute), SSOSID: sid, SSOIssuer: issuer, Stage: store.StagePending}
		var wg sync.WaitGroup
		var redeemErr error
		wg.Add(2)
		go func() { // what handleCLIExchange does
			defer wg.Done()
			redeemErr = st.Sessions().RedeemCLICode(ctx, code.CodeHash, func(*store.CLICode) (*store.Session, error) { return sess, nil })
		}()
		go func() {
			defer wg.Done()
			if err := st.Sessions().EndSSOSession(ctx, issuer, sid, time.Now().Add(time.Minute)); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if redeemErr != nil && !errors.Is(redeemErr, store.ErrSSOSessionEnded) {
			t.Fatal(redeemErr)
		}
		if _, err := st.Sessions().GetSession(ctx, sess.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: a CLI session survived its logout fence (%v, redeem %v)", i, err, redeemErr)
		}
	}
}

// §7.6: only a bearer caller gets the active token in the body; a browser gets the cookie
// alone, so script on the page never sees a session token.
func TestBrowserExchangeNeverReturnsTheToken(t *testing.T) {
	srv, _, f := ssoServer(t)
	c := pending(t, srv, f, "browser", "sid-1", mfaClaims)
	var offer struct{ Secret string }
	if w := post(srv, c, "/api/auth/stepup/enroll", nil); w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &offer) != nil {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	code, _ := totp.Code(offer.Secret, time.Now())
	w := post(srv, c, "/api/auth/stepup/enroll/confirm", map[string]string{"code": code})
	if w.Code != http.StatusOK || sessionCookie(w) == nil || bytes.Contains(w.Body.Bytes(), []byte("token")) {
		t.Fatalf("browser exchange: %d %s", w.Code, w.Body)
	}
}

// §7.6 with §7.3 rule 6: a factor reset voids outstanding CLI login codes, so a code issued
// before the reset redeems nothing afterwards.
func TestFactorResetVoidsOutstandingCLICodes(t *testing.T) {
	srv, st, f := ssoServer(t)
	enroll(t, srv, pending(t, srv, f, "reset-me", "sid-1", mfaClaims))
	code := cliCode(t, cliCallback(t, srv, f, "reset-me", "sid-2"))
	u, err := st.Users().GetUserByUsername(context.Background(), "reset-me")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MFA().DeleteFactor(context.Background(), u.ID, &store.AuditRecord{Action: "admin.factor_reset"}); err != nil {
		t.Fatal(err)
	}
	if w := cliExchange(srv, code, cliVerifier); w.Code != http.StatusUnauthorized {
		t.Fatalf("a pre-reset CLI code after the reset: %d %s", w.Code, w.Body)
	}
}
