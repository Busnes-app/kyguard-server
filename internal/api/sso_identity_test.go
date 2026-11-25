package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
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
	oidcLogin := ssoLoginVia(t, srv, other, "oidc", "same-sub", "shared-sid", "same-sub-oidc")
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

// ssoLoginVia is ssoLoginClaims against the named provider's routes, with a username.
func ssoLoginVia(t *testing.T, srv *api.Server, f *fakeKySignOn, provider, sub, sid, username string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/sso/"+provider+"/login", nil))
	loc, err := url.Parse(w.Header().Get("Location"))
	if w.Code != http.StatusFound || err != nil {
		t.Fatalf("%s login redirect: %d %s", provider, w.Code, w.Body.String())
	}
	q := loc.Query()
	f.idToken = f.sign(t, "", map[string]any{"sub": sub, "sid": sid, "nonce": q.Get("nonce"), "preferred_username": username, "auth_time": time.Now().Unix()})
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
