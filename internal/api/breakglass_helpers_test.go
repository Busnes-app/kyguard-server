package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

const breakGlassPassword = "BreakGlassPassword-0123"

// breakGlass is a test break-glass admin with a known password and TOTP secret.
type breakGlass struct {
	ID, Username, Password, Secret string
	used                           int
}

// newBreakGlass creates a break-glass admin the way `kyguard-server break-glass create` does.
func newBreakGlass(t *testing.T, srv *api.Server, st store.Store, username string) *breakGlass {
	t.Helper()
	hash, err := password.Hash(breakGlassPassword)
	if err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "usr_" + username, Username: username, PasswordHash: hash, Role: "admin", Status: "active"}
	secret, sealed, err := api.FactorsForTest(srv).NewSecret(u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.MFA().CreateBreakGlass(context.Background(), u, &store.MFAFactor{ID: "mfa_" + username, SecretEnc: sealed}, &store.AuditRecord{Action: "break_glass.created"}); err != nil {
		t.Fatal(err)
	}
	return &breakGlass{ID: u.ID, Username: username, Password: breakGlassPassword, Secret: secret}
}

var codeMu sync.Mutex

// Code returns an unspent code. totp.Validate accepts one step either side, so a user gets two
// codes per 30 seconds that stay valid across a step boundary: the current step, then the next.
func (b *breakGlass) Code(t *testing.T) string {
	t.Helper()
	codeMu.Lock()
	defer codeMu.Unlock()
	if b.used >= 2 {
		t.Fatalf("%s needs a third code inside 30 s; use another account", b.Username)
	}
	code, err := totp.Code(b.Secret, time.Now().Add(time.Duration(b.used)*totp.Period*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	b.used++
	return code
}

// WrongCode returns a well-formed code that matches no step near now, so a refusal never
// rests on luck: any fixed code, 000000 included, is sometimes a valid one.
func (b *breakGlass) WrongCode(t *testing.T) string {
	t.Helper()
	return wrongCode(t, b.Secret, time.Now())
}

func wrongCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	near := map[string]bool{}
	for step := -3; step <= 3; step++ {
		code, err := totp.Code(secret, at.Add(time.Duration(step)*totp.Period*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		near[code] = true
	}
	for n := 0; ; n++ {
		if code := fmt.Sprintf("%06d", n); !near[code] {
			return code
		}
	}
}

func (b *breakGlass) loginBody(t *testing.T) []byte {
	body, _ := json.Marshal(map[string]string{"username": b.Username, "password": b.Password, "totp_code": b.Code(t)})
	return body
}

// Login signs in with password and code and states a reason, so privileged routes admit the
// session. It returns the session cookie.
func (b *breakGlass) Login(t *testing.T, srv *api.Server) *http.Cookie {
	t.Helper()
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewReader(b.loginBody(t))))
	if w.Code != http.StatusOK {
		t.Fatalf("break-glass login as %s: %d %s", b.Username, w.Code, w.Body)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie")
	}
	req := httptest.NewRequest(http.MethodPost, "/api/auth/break-glass/reason", bytes.NewReader([]byte(`{"reason":"test"}`)))
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
	req.Header.Set(auth.HeaderCSRF, "test-csrf")
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("break-glass reason: %d %s", w.Code, w.Body)
	}
	return cookie
}

// ssoSession creates an SSO user with role and an active session for it, as a completed SSO
// login would, and returns the session cookie.
func ssoSession(t *testing.T, st store.Store, username, role string) *http.Cookie {
	t.Helper()
	ctx := context.Background()
	u := &store.User{ID: "usr_" + username, Username: username, Role: role, Status: "active", SSOProvider: "kysignon", SSOSubject: "sub-" + username}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	raw := crypto.RandomHex(32)
	now := time.Now().UTC()
	if err := st.Sessions().CreateSession(ctx, &store.Session{TokenHash: crypto.SHA256Hex([]byte(raw)), UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Hour), StepupAt: &now}, ""); err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: auth.SessionCookieName, Value: raw}
}
