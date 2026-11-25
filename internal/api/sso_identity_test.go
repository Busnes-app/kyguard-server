package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/sso"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Acceptance 7: an ID token whose auth_time is missing or older than 120 seconds is refused.
func TestStaleAuthTimeIsRefused(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	f := newFakeKySignOn(t)
	cfg.SSO.KySignOnIssuer, cfg.SSO.KySignOnClientID, cfg.SSO.AutoProvision = f.issuer, "client", true
	srv = api.NewServer(cfg, st)
	for name, authTime := range map[string]any{
		"old":    time.Now().Add(-121 * time.Second).Unix(),
		"future": time.Now().Add(5 * time.Minute).Unix(),
		"absent": nil,
	} {
		extra := map[string]any{"auth_time": authTime}
		if w := ssoLoginClaims(t, srv, f, "pat", "sid-"+name, time.Now(), extra); w.Code != http.StatusUnauthorized || sessionCookie(w) != nil {
			t.Errorf("%s auth_time: %d, want 401 and no session", name, w.Code)
		}
	}
	if w := ssoLogin(t, srv, f, "pat", "sid-fresh"); w.Code != http.StatusFound {
		t.Fatalf("fresh auth_time: %d %s", w.Code, w.Body)
	}
}

// §7.2: the authorization request asks for a fresh login (max_age=0) and, for KySignOn, its
// MFA acr.
func TestAuthorizationRequestAsksForFreshMFA(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	f := newFakeKySignOn(t)
	cfg.SSO.KySignOnIssuer, cfg.SSO.KySignOnClientID = f.issuer, "client"
	srv = api.NewServer(cfg, st)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sso/kysignon/login", nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound {
		t.Fatalf("%d %v", w.Code, err)
	}
	if q := loc.Query(); q.Get("max_age") != "0" || q.Get("acr_values") != "urn:kysignon:acr:mfa" {
		t.Fatalf("authorization request %s", loc.RawQuery)
	}
}

// Acceptance 10: two issuers with the same subject are two users, and a back-channel logout
// for a sid ends only the issuing provider's login.
func TestIssuerIsPartOfTheIdentity(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()
	ky, other := newFakeKySignOn(t), newFakeKySignOn(t)
	cfg.SSO.KySignOnIssuer, cfg.SSO.KySignOnClientID, cfg.SSO.AutoProvision = ky.issuer, "client", true
	cfg.SSO.GenericOIDCIssuer, cfg.SSO.GenericOIDCClientID = other.issuer, "client"
	srv = api.NewServer(cfg, st)

	kyLogin := ssoLogin(t, srv, ky, "same-sub", "shared-sid")
	if kyLogin.Code != http.StatusFound {
		t.Fatalf("KySignOn login: %d %s", kyLogin.Code, kyLogin.Body)
	}
	oidcLogin := ssoLoginVia(t, srv, other, "oidc", "same-sub", "shared-sid", "same-sub-oidc", nil)
	if oidcLogin.Code != http.StatusFound {
		t.Fatalf("OIDC login: %d %s", oidcLogin.Code, oidcLogin.Body)
	}
	a, errA := st.Users().GetUserBySSO(ctx, ky.issuer, "same-sub")
	b, errB := st.Users().GetUserBySSO(ctx, other.issuer, "same-sub")
	if errA != nil || errB != nil || a.ID == b.ID || a.SSOProvider != "kysignon" || b.SSOProvider != "oidc" {
		t.Fatalf("one identity per issuer: %+v %v / %+v %v", a, errA, b, errB)
	}
	// KySignOn's logout for "shared-sid" ends its own login, not the OIDC one with that sid.
	if w := postLogout(srv, ky.logoutToken(t, "same-sub", "shared-sid")); w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	if signedIn(srv, sessionCookie(kyLogin)) || !signedIn(srv, sessionCookie(oidcLogin)) {
		t.Fatal("a logout from one issuer reached another issuer's login with the same sid")
	}
	if _, err := st.Users().GetUserBySSO(ctx, "", "same-sub"); err != store.ErrNotFound {
		t.Fatalf("a lookup without an issuer matched: %v", err)
	}
}

// §7.3: a generic OIDC sign-in, even an admin's with fresh IdP MFA, yields only a pending
// session. It names its user and signs out, and authorizes nothing else until TOTP step-up.
func TestOIDCSignInIsPendingUntilStepUp(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	f := newFakeKySignOn(t)
	cfg.SSO.GenericOIDCIssuer, cfg.SSO.GenericOIDCClientID, cfg.SSO.AutoProvision = f.issuer, "client", true
	srv = api.NewServer(cfg, st)

	w := ssoLoginVia(t, srv, f, "oidc", "ada-sub", "sid-ada", "ada", map[string]any{"roles": []string{"admin"}, "amr": []string{"pwd", "otp"}})
	c := sessionCookie(w)
	if w.Code != http.StatusFound || c == nil {
		t.Fatalf("OIDC callback: %d %s", w.Code, w.Body)
	}
	sess, err := st.Sessions().GetSession(context.Background(), crypto.SHA256Hex([]byte(c.Value)))
	if err != nil || sess.Stage != store.StagePending || time.Until(sess.ExpiresAt) > auth.PendingTTL {
		t.Fatalf("OIDC session %+v %v, want pending for at most %s", sess, err, auth.PendingTTL)
	}
	if !signedIn(srv, c) {
		t.Fatal("a pending session cannot name its user")
	}
	req := httptest.NewRequest(http.MethodGet, "/api/settings", nil)
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "db_driver") {
		t.Error("a pending session read the signed-in settings")
	}
	for _, path := range []string{"/api/admin/users", "/api/backup/status"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(c)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("pending session on %s: %d, want 401", path, rec.Code)
		}
	}
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	for _, ck := range w.Result().Cookies() {
		req.AddCookie(ck)
		if ck.Name == auth.CSRFCookieName {
			req.Header.Set(auth.HeaderCSRF, ck.Value)
		}
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || signedIn(srv, c) {
		t.Fatalf("logout: %d %s, or it left the pending session", rec.Code, rec.Body)
	}
}

// ssoLoginVia is ssoLoginClaims against the named provider's routes, with a username.
func ssoLoginVia(t *testing.T, srv *api.Server, f *fakeKySignOn, provider, sub, sid, username string, extra map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sso/"+provider+"/login", nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil {
		t.Fatalf("%s login redirect: %d %s", provider, w.Code, w.Body.String())
	}
	q := loc.Query()
	claims := map[string]any{"sub": sub, "sid": sid, "nonce": q.Get("nonce"), "preferred_username": username, "auth_time": time.Now().Unix()}
	for k, v := range extra {
		claims[k] = v
	}
	f.idToken = f.sign(t, "", claims)
	req := httptest.NewRequest(http.MethodGet, "/api/sso/"+provider+"/callback?code=c&state="+q.Get("state"), nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// A SCIM externalId correction that lands between the callback's lookup and its adoption
// must not let the sign-in through for a row that no longer carries the token's identity.
func TestAdoptionRevalidatesTheIdentity(t *testing.T) {
	_, st, _ := setupTestServer(t)
	ctx := context.Background()
	row := &store.User{ID: "usr_s", Username: "sam", Role: "user", Status: "active", SSOProvider: "scim", SSOSubject: "sub-a", SSOIssuer: "https://idp", SCIMManaged: true}
	if err := st.Users().CreateUser(ctx, row); err != nil {
		t.Fatal(err)
	}
	stale, err := st.Users().GetUserBySSO(ctx, "https://idp", "sub-a") // the callback's lookup
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := st.Users().GetUserByID(ctx, "usr_s")
	fresh.SSOSubject = "sub-b"
	if err := st.Users().UpdateSCIMProfile(ctx, fresh, fresh.Role, fresh.Status, "sub-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := sso.AdoptSCIMUser(ctx, st.Users(), stale, "kysignon"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("adoption of a re-identified row: %v, want ErrConflict", err)
	}
	if u, _ := st.Users().GetUserByID(ctx, "usr_s"); u.SSOProvider != "scim" {
		t.Fatalf("the row was linked anyway: %+v", u)
	}
}
