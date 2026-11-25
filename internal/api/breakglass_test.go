package api_test

import (
	"context"
	"database/sql"
	"errors"
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
	if err := st.MFA().ReplaceFactor(ctx, b.ID, "mfa_copied", fa.SecretEnc, &store.AuditRecord{Action: "test"}); err != nil {
		t.Fatal(err)
	}
	if _, err := api.FactorsForTest(srv).Check(ctx, b.ID, "", a.Code(t)); err == nil {
		t.Fatal("alpha's sealed secret verified a code for bravo")
	}
}

// A host TOTP reset that lands between a login's code check and its session insert wins: the
// login, authorized by the replaced factor, gets no session.
func TestTOTPResetFencesAnInFlightLogin(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()
	bg := newBreakGlass(t, srv, st, "root")
	factorID, err := api.FactorsForTest(srv).Check(ctx, bg.ID, "", bg.Code(t))
	if err != nil {
		t.Fatal(err)
	}
	_, sealed, err := api.FactorsForTest(srv).NewSecret(bg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MFA().ReplaceFactor(ctx, bg.ID, "mfa_new", sealed, &store.AuditRecord{Action: "break_glass.totp_reset"}); err != nil {
		t.Fatal(err)
	}
	user, err := st.Users().GetUserByID(ctx, bg.ID)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	_, _, err = auth.NewSessionManager(st, cfg.Security).IssueBreakGlassSession(ctx, w, httptest.NewRequest(http.MethodPost, "/api/auth/login", nil), user, factorID, &store.AuditRecord{Action: "auth.break_glass_login"})
	if !errors.Is(err, store.ErrNotFound) || len(w.Result().Cookies()) != 0 {
		t.Fatalf("session from a replaced factor: %v, cookies %v", err, w.Result().Cookies())
	}
}

// A sign-in or a reason whose audit record cannot be written leaves nothing behind: no
// session and no cookies, no recorded reason, and a retry works once auditing does.
func TestFailedAuditLeavesNoSessionOrReason(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()
	db, err := sql.Open(map[string]string{"sqlite": "sqlite", "postgres": "pgx"}[cfg.Database.Driver], cfg.Database.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	breakAudit := func(on bool) {
		t.Helper()
		from, to := "audit_records", "audit_records_off"
		if !on {
			from, to = to, from
		}
		if _, err := db.Exec("ALTER TABLE " + from + " RENAME TO " + to); err != nil {
			t.Fatal(err)
		}
	}
	bg := newBreakGlass(t, srv, st, "root")
	sessions := func() int {
		var n int
		if err := db.QueryRow("SELECT COUNT(1) FROM sessions").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	breakAudit(true)
	w := loginWithCode(t, srv, "root", bg.Password, bg.Code(t), "192.0.2.1:1")
	breakAudit(false)
	if w.Code != http.StatusServiceUnavailable || sessionCookie(w) != nil || sessions() != 0 {
		t.Fatalf("unaudited sign-in: %d, cookie %v, %d sessions", w.Code, sessionCookie(w), sessions())
	}

	other := newBreakGlass(t, srv, st, "other")
	w = loginWithCode(t, srv, "other", other.Password, other.Code(t), "192.0.2.2:1")
	session := sessionCookie(w)
	if w.Code != http.StatusOK || session == nil {
		t.Fatalf("login: %d", w.Code)
	}
	reason := func() int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/reason", strings.NewReader(`{"reason":"outage"}`))
		req.AddCookie(session)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "c"})
		req.Header.Set(auth.HeaderCSRF, "c")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w.Code
	}
	breakAudit(true)
	code := reason()
	breakAudit(false)
	sess, err := st.Sessions().GetSession(ctx, crypto.SHA256Hex([]byte(session.Value)))
	if err != nil {
		t.Fatal(err)
	}
	if code != http.StatusServiceUnavailable || sess.BreakGlassReason != "" {
		t.Fatalf("unaudited reason: %d, stored %q", code, sess.BreakGlassReason)
	}
	if code := reason(); code != http.StatusOK {
		t.Fatalf("retry after auditing recovered: %d", code)
	}
}

// The reason limit is 500 characters, as the form counts them, not 500 bytes.
func TestBreakGlassReasonCountsCharacters(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	w := loginWithCode(t, srv, "root", bg.Password, bg.Code(t), "192.0.2.1:1")
	c := sessionCookie(w)
	reason := func(r string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/reason", strings.NewReader(`{"reason":"`+r+`"}`))
		req.AddCookie(c)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "c"})
		req.Header.Set(auth.HeaderCSRF, "c")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w.Code
	}
	if code := reason(strings.Repeat("障", 501)); code != http.StatusBadRequest {
		t.Fatalf("501 characters: %d", code)
	}
	if code := reason(strings.Repeat("障", 500)); code != http.StatusOK { // 1500 bytes
		t.Fatalf("500 multibyte characters: %d", code)
	}
}
