package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// ssoServer is a test server signing in through a fake KySignOn.
func ssoServer(t *testing.T) (*api.Server, store.Store, *fakeKySignOn) {
	t.Helper()
	_, st, cfg := setupTestServer(t)
	f := newFakeKySignOn(t)
	cfg.SSO.KySignOnIssuer, cfg.SSO.KySignOnClientID, cfg.SSO.AutoProvision = f.issuer, "client", true
	return api.NewServer(cfg, st), st, f
}

// pending signs sub in through SSO with claims and returns the pending session cookie.
func pending(t *testing.T, srv *api.Server, f *fakeKySignOn, sub, sid string, claims map[string]any) *http.Cookie {
	t.Helper()
	w := ssoLoginClaims(t, srv, f, sub, sid, time.Now(), claims)
	c := sessionCookie(w)
	if w.Code != http.StatusFound || c == nil {
		t.Fatalf("SSO callback: %d %s", w.Code, w.Body)
	}
	return c
}

func post(srv *api.Server, c *http.Cookie, path string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	req.AddCookie(c)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "c"})
	req.Header.Set(auth.HeaderCSRF, "c")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

var mfaClaims = map[string]any{"amr": []string{"pwd", "mfa"}, "roles": []string{"admin"}}

// enroll runs first-factor enrollment on a pending session and returns the secret and the
// active session cookie. The enrolling code is the current step's.
func enroll(t *testing.T, srv *api.Server, c *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	w := post(srv, c, "/api/auth/stepup/enroll", nil)
	var offer struct {
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &offer) != nil || offer.Secret == "" || !strings.HasPrefix(offer.OTPAuthURI, "otpauth://totp/") {
		t.Fatalf("enroll: %d %s", w.Code, w.Body)
	}
	code, _ := totp.Code(offer.Secret, time.Now())
	w = post(srv, c, "/api/auth/stepup/enroll/confirm", map[string]string{"code": code})
	active := sessionCookie(w)
	if w.Code != http.StatusOK || active == nil {
		t.Fatalf("confirm: %d %s", w.Code, w.Body)
	}
	return offer.Secret, active
}

func status(srv *api.Server, method, path string, c *http.Cookie, bearer bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if bearer {
		req.Header.Set("Authorization", "Bearer "+c.Value)
	} else {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// Acceptance 4: SSO sign-in yields a pending session that every session route refuses and
// that sees only the public settings, by cookie and by Bearer. A valid TOTP exchange kills the
// pending token and issues a new 12-hour one that works.
func TestSSOSignInIsPendingUntilStepUp(t *testing.T) {
	srv, st, f := ssoServer(t)
	if err := st.Settings().SetSetting(context.Background(), "scim_token", "secret-bearer"); err != nil {
		t.Fatal(err)
	}
	c := pending(t, srv, f, "amy", "sid-1", mfaClaims)
	for _, bearer := range []bool{false, true} {
		if w := status(srv, "GET", "/api/admin/users", c, bearer); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "stepup_required") {
			t.Fatalf("pending session on an admin route (bearer %v): %d %s", bearer, w.Code, w.Body)
		}
		settings := status(srv, "GET", "/api/settings", c, bearer).Body.String()
		if strings.Contains(settings, "db_driver") || strings.Contains(settings, "extra_settings") || strings.Contains(settings, "scim_enabled") {
			t.Fatalf("pending session (bearer %v) saw private settings: %s", bearer, settings)
		}
	}
	if w := status(srv, "GET", "/api/auth/me", c, false); !strings.Contains(w.Body.String(), `"stepup":{"can_enroll":true,"enrolled":false,"required":true}`) {
		t.Fatalf("me for a pending session: %s", w.Body)
	}

	_, active := enroll(t, srv, c)
	if signedIn(srv, c) {
		t.Fatal("the pending token survived the exchange")
	}
	if active.Value == c.Value {
		t.Fatal("the pending token became the active one")
	}
	if w := status(srv, "GET", "/api/admin/users", active, false); w.Code != http.StatusOK {
		t.Fatalf("active session: %d %s", w.Code, w.Body)
	}
	sess, err := st.Sessions().GetSession(context.Background(), crypto.SHA256Hex([]byte(active.Value)))
	if err != nil {
		t.Fatal(err)
	}
	if life := time.Until(sess.ExpiresAt); life > 12*time.Hour || life < 12*time.Hour-time.Minute || sess.StepupAt == nil || sess.SSOSID != "sid-1" {
		t.Fatalf("active session %+v lives %v", sess, life)
	}
}

// Acceptance 5: a code is single-use; the fifth failure ends the pending session; after ten
// failures for a user in 15 minutes even a correct code fails.
func TestStepUpCodeLimits(t *testing.T) {
	srv, _, f := ssoServer(t)
	secret, _ := enroll(t, srv, pending(t, srv, f, "bo", "sid-0", mfaClaims))
	spent, _ := totp.Code(secret, time.Now())

	c := pending(t, srv, f, "bo", "sid-1", mfaClaims)
	if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": spent}); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed enrollment code: %d", w.Code)
	}
	for i := 2; i <= auth.SessionCodeLimit; i++ {
		if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": wrongCode(t, secret, time.Now())}); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d", i, w.Code)
		}
	}
	if signedIn(srv, c) {
		t.Fatal("the pending session survived its fifth failed code")
	}
	c = pending(t, srv, f, "bo", "sid-2", mfaClaims)
	for i := 1; i <= auth.UserCodeLimit-auth.SessionCodeLimit; i++ {
		post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": wrongCode(t, secret, time.Now())})
	}
	c = pending(t, srv, f, "bo", "sid-3", mfaClaims)
	next, _ := totp.Code(secret, time.Now().Add(totp.Period*time.Second))
	if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": next}); w.Code != http.StatusUnauthorized {
		t.Fatalf("correct code after ten failures: %d, want 401", w.Code)
	}
}

// Acceptance 6: a token whose amr is only otp (no mfa, no MFA acr) cannot enroll a factor,
// and the block is audited for admins.
func TestEnrollmentNeedsIdPMFA(t *testing.T) {
	srv, st, f := ssoServer(t)
	c := pending(t, srv, f, "cy", "sid-1", map[string]any{"amr": []string{"otp"}, "acr": "urn:other"})
	if w := post(srv, c, "/api/auth/stepup/enroll", nil); w.Code != http.StatusForbidden {
		t.Fatalf("enroll without IdP MFA: %d %s", w.Code, w.Body)
	}
	if w := post(srv, c, "/api/auth/stepup/enroll/confirm", map[string]string{"code": "123456"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("confirm without an offer: %d", w.Code)
	}
	recs, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Action == "auth.enrollment_blocked" {
			return
		}
	}
	t.Fatal("no auth.enrollment_blocked audit record")
}

// Acceptance 7: a back-channel logout between the callback and the TOTP exchange, by sid or
// by subject from the same issuer, makes the exchange fail; the same sid from another issuer
// does not.
func TestLogoutBeforeStepUpEndsTheSignIn(t *testing.T) {
	srv, _, f := ssoServer(t)
	other := newFakeKySignOn(t)
	codes := map[string]string{}
	for _, sub := range []string{"di", "ed"} {
		secret, _ := enroll(t, srv, pending(t, srv, f, sub, "sid-0-"+sub, mfaClaims))
		codes[sub], _ = totp.Code(secret, time.Now().Add(totp.Period*time.Second))
	}

	// By sid.
	c := pending(t, srv, f, "di", "sid-x", mfaClaims)
	if w := postLogout(srv, f.logoutToken(t, "di", "sid-x")); w.Code != http.StatusOK {
		t.Fatalf("sid logout: %d", w.Code)
	}
	if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": codes["di"]}); w.Code == http.StatusOK {
		t.Fatal("exchange after a sid logout succeeded")
	}
	// By subject, covering logins issued before its iat.
	c = pending(t, srv, f, "ed", "sid-z", mfaClaims)
	subject := f.sign(t, "logout+jwt", map[string]any{"sub": "ed", "jti": "j", "iat": time.Now().Add(time.Minute).Unix(), "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}})
	if w := postLogout(srv, subject); w.Code != http.StatusOK {
		t.Fatalf("subject logout: %d", w.Code)
	}
	if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": codes["ed"]}); w.Code == http.StatusOK {
		t.Fatal("exchange after a subject logout succeeded")
	}
	// Another issuer's logout for the same sid is refused by this server's client and ends
	// nothing.
	c = pending(t, srv, f, "di", "sid-y", mfaClaims)
	if w := postLogout(srv, other.logoutToken(t, "di", "sid-y")); w.Code != http.StatusBadRequest {
		t.Fatalf("foreign issuer's logout: %d", w.Code)
	}
	if w := post(srv, c, "/api/auth/stepup/totp", map[string]string{"code": codes["di"]}); w.Code != http.StatusOK {
		t.Fatalf("exchange after a foreign issuer's logout: %d %s", w.Code, w.Body)
	}
}

// Acceptance 7, concurrent: a back-channel logout racing the TOTP exchange never leaves an
// active session behind its fence (both drivers; the spec requires PostgreSQL).
func TestLogoutRacingStepUpLeavesNoActiveSession(t *testing.T) {
	_, st, _ := setupTestServer(t)
	ctx := context.Background()
	const issuer = "https://idp.race"
	u := &store.User{ID: "usr_race", Username: "race", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "race", SSOIssuer: issuer}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	iat := time.Now().UTC().Add(-time.Second)
	for i := range 25 {
		sid := fmt.Sprintf("sid-%d", i)
		p := &store.Session{TokenHash: "pending-" + sid, UserID: u.ID, CreatedAt: iat, ExpiresAt: time.Now().Add(time.Minute), SSOSID: sid, SSOIssuer: issuer, Stage: store.StagePending}
		if err := st.Sessions().CreateSession(ctx, p, ""); err != nil {
			t.Fatal(err)
		}
		active := &store.Session{TokenHash: "active-" + sid, UserID: u.ID, CreatedAt: iat, ExpiresAt: time.Now().Add(time.Hour), SSOSID: sid, SSOIssuer: issuer}
		var wg sync.WaitGroup
		var exchangeErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			exchangeErr = st.Sessions().ExchangeSession(ctx, p.TokenHash, "", active, nil)
		}()
		go func() {
			defer wg.Done()
			if err := st.Sessions().EndSSOSession(ctx, issuer, sid, time.Now().Add(time.Minute)); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		if exchangeErr != nil && !errors.Is(exchangeErr, store.ErrNotFound) && !errors.Is(exchangeErr, store.ErrSSOSessionEnded) {
			t.Fatal(exchangeErr)
		}
		if _, err := st.Sessions().GetSession(ctx, active.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: an active session survived its logout fence (%v, exchange %v)", i, err, exchangeErr)
		}
	}
}

// §7.2 session binding: the active session keeps the ID token's original iat, so a subject
// logout dated after that iat but before the exchange still ends it.
func TestSubjectLogoutUsesTheOriginalIat(t *testing.T) {
	srv, _, f := ssoServer(t)
	w := ssoLoginClaims(t, srv, f, "fi", "sid-1", time.Now().Add(-90*time.Second), mfaClaims)
	_, active := enroll(t, srv, sessionCookie(w))
	logout := f.sign(t, "logout+jwt", map[string]any{"sub": "fi", "jti": "j", "iat": time.Now().Add(-60 * time.Second).Unix(), "events": map[string]any{"http://schemas.openid.net/event/backchannel-logout": map[string]any{}}})
	if w := postLogout(srv, logout); w.Code != http.StatusOK {
		t.Fatalf("logout: %d", w.Code)
	}
	if signedIn(srv, active) {
		t.Fatal("a subject logout after the token's iat left the exchanged session alive")
	}
}
