package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Acceptance 9: local sign-in is for break-glass accounts only, even with the right password.
func TestOnlyBreakGlassSignsInLocally(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	hash, _ := password.Hash(breakGlassPassword)
	if err := st.Users().CreateUser(context.Background(), &store.User{ID: "usr_sso", Username: "sso", PasswordHash: hash, Role: "admin", Status: "active", SSOProvider: "kysignon", SSOSubject: "s"}); err != nil {
		t.Fatal(err)
	}
	if w := loginWithCode(t, srv, "sso", breakGlassPassword, "123456", "192.0.2.1:1"); w.Code != http.StatusForbidden {
		t.Fatalf("SSO account with its password: %d %s, want 403", w.Code, w.Body)
	}
}

// Acceptance 9: a break-glass account needs its code in the same request; a wrong one fails.
func TestBreakGlassSignInNeedsTheCode(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	if w := loginWithCode(t, srv, "root", bg.Password, "", "192.0.2.1:1"); w.Code != http.StatusBadRequest {
		t.Fatalf("no totp_code: %d", w.Code)
	}
	if w := loginWithCode(t, srv, "root", bg.Password, "000000", "192.0.2.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong totp_code: %d", w.Code)
	}
}

// Acceptance 9: a wrong password never reaches the TOTP counter, so password guessing cannot
// burn the account's code allowance.
func TestWrongPasswordLeavesTheTOTPCounterUntouched(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	for i := 0; i < 3; i++ {
		if w := loginWithCode(t, srv, "root", "WrongPassword-0123", "000000", "192.0.2.1:1"); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong password: %d", w.Code)
		}
	}
	id, perUser, _, err := st.MFA().ReserveAttempt(context.Background(), bg.ID, "", auth.CodeWindow)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.MFA().ReleaseAttempt(context.Background(), id)
	if perUser != 1 {
		t.Fatalf("wrong passwords left %d code attempts counted", perUser-1)
	}
}

// Acceptance 5: a code is accepted once.
func TestReplayedCodeFails(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	code := bg.Code(t)
	if w := loginWithCode(t, srv, "root", bg.Password, code, "192.0.2.1:1"); w.Code != http.StatusOK {
		t.Fatalf("first use: %d %s", w.Code, w.Body)
	}
	if w := loginWithCode(t, srv, "root", bg.Password, code, "192.0.2.2:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d, want 401", w.Code)
	}
}

// Acceptance 5: after 10 failed codes in 15 minutes for one user, the next code fails even
// when correct. Each guess comes from its own client, so the per-client password windows are
// not what refuses it.
func TestUserCodeLimitRefusesACorrectCode(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	for i := 1; i <= auth.UserCodeLimit; i++ {
		if w := loginWithCode(t, srv, "root", bg.Password, "000000", "192.0.2."+strconv.Itoa(i)+":1"); w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: %d", i, w.Code)
		}
	}
	if w := loginWithCode(t, srv, "root", bg.Password, bg.Code(t), "198.51.100.1:1"); w.Code != http.StatusUnauthorized {
		t.Fatalf("correct code past the limit: %d, want 401", w.Code)
	}
}

// §7.4: a break-glass session ends 30 minutes after sign-in, every attempt is a critical audit
// record, and the reason is given once.
func TestBreakGlassSessionShape(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	ctx := context.Background()
	bg := newBreakGlass(t, srv, st, "root")
	_ = loginWithCode(t, srv, "root", "WrongPassword-0123", "000000", "192.0.2.1:1")
	cookie := bg.Login(t, srv)
	sess, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(cookie.Value)))
	if err != nil {
		t.Fatal(err)
	}
	if life := time.Until(sess.ExpiresAt); life > auth.BreakGlassTTL || life < auth.BreakGlassTTL-time.Minute {
		t.Fatalf("break-glass session lives %v", life)
	}
	if sess.StepupAt == nil || sess.BreakGlassReason != "test" {
		t.Fatalf("session %+v", sess)
	}
	records, _, err := st.Audit().ListAuditRecords(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	outcomes := map[string]bool{}
	for _, r := range records {
		if r.Action == "auth.break_glass_login" && strings.Contains(r.Details, "severity=critical") {
			outcomes[strings.TrimPrefix(r.Details, "severity=critical outcome=")] = true
		}
	}
	if !outcomes["bad_password"] || !outcomes["success"] {
		t.Fatalf("audited outcomes %v", outcomes)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/reason", strings.NewReader(`{"reason":"again"}`))
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "c"})
	req.Header.Set(auth.HeaderCSRF, "c")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusConflict {
		t.Fatalf("second reason: %d", w.Code)
	}
}

// §7.3 rule 4: a sealed secret copied onto another user's factor row does not open there, so
// a database writer cannot hand one account's authenticator to another.
func TestSealedFactorIsBoundToItsUser(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	ctx := context.Background()
	a, b := newBreakGlass(t, srv, st, "alpha"), newBreakGlass(t, srv, st, "bravo")
	fa, err := st.MFA().GetFactor(ctx, a.ID, store.FactorTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MFA().ReplaceFactor(ctx, b.ID, fa.SecretEnc); err != nil {
		t.Fatal(err)
	}
	if err := api.FactorsForTest(srv).Check(ctx, b.ID, "", a.Code(t)); err == nil {
		t.Fatal("alpha's sealed secret verified a code for bravo")
	}
}
