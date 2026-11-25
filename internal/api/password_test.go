package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func TestForcedPasswordReplacement(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	ctx := context.Background()
	bg := newBreakGlass(t, srv, st, "admin")
	oldPassword, newPassword := bg.Password, "ReplacementPassword456!"
	user, err := st.Users().GetUserByID(ctx, bg.ID)
	if err != nil {
		t.Fatal(err)
	}
	user.MustChangePassword = true
	if err := st.Users().UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	manager := auth.NewSessionManager(st, cfg.Security)
	login := httptest.NewRecorder()
	_, token, err := manager.IssueSession(ctx, login, httptest.NewRequest("POST", "/api/auth/login", nil), user)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, cookie, csrf bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie {
			for _, c := range login.Result().Cookies() {
				req.AddCookie(c)
				if csrf && c.Name == auth.CSRFCookieName {
					req.Header.Set(auth.HeaderCSRF, c.Value)
				}
			}
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	for _, cookies := range []bool{false, true} {
		for _, route := range []struct{ method, path string }{{"GET", "/api/backup/status"}, {"POST", "/api/settings/theme"}, {"POST", "/api/backup/export-capsule"}} {
			w := call(route.method, route.path, `{"theme":"oled"}`, cookies, true)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "password_change_required") {
				t.Fatalf("restricted %s: %d %s", route.path, w.Code, w.Body)
			}
		}
		w := call("GET", "/api/settings", "", cookies, true)
		if strings.Contains(w.Body.String(), "extra_settings") || strings.Contains(w.Body.String(), "db_driver") {
			t.Fatal("restricted settings leaked", w.Body)
		}
	}
	if w := call("GET", "/api/auth/me", "", true, true); !strings.Contains(w.Body.String(), `"must_change_password":true`) {
		t.Fatal(w.Body)
	}
	body := func(old, new, code string) string {
		b, _ := json.Marshal(map[string]string{"current_password": old, "new_password": new, "totp_code": code})
		return string(b)
	}
	if w := call("POST", "/api/auth/change-password", body(oldPassword, newPassword, "000000"), true, false); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	for _, bad := range []struct {
		old, new string
		status   int
	}{{oldPassword, "Fifteen-chars-1", 400}, {oldPassword, oldPassword, 400}, {"incorrect", newPassword, 401}, {oldPassword, newPassword, 401}} {
		if w := call("POST", "/api/auth/change-password", body(bad.old, bad.new, "000000"), true, true); w.Code != bad.status {
			t.Fatal(w.Code, w.Body)
		}
	}
	if w := call("POST", "/api/auth/change-password", body(oldPassword, newPassword, bg.Code(t)), true, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	if w := call("GET", "/api/auth/me", "", false, true); strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("old session survived")
	}
	updated, err := st.Users().GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.MustChangePassword {
		t.Fatal("flag still set")
	}
	if ok, _ := password.Verify(newPassword, updated.PasswordHash); !ok {
		t.Fatal("new password does not verify")
	}
	if _, _, err := manager.IssueSession(ctx, httptest.NewRecorder(), httptest.NewRequest("POST", "/api/auth/login", nil), user); err == nil {
		t.Fatal("stale password login issued a session")
	}
	if w := loginStatusFor(t, srv, "admin", oldPassword, "192.0.2.1:1"); w.Code != 401 {
		t.Fatal("old password after replacement", w.Code, w.Body)
	}
	if w := loginWithCode(t, srv, "admin", newPassword, bg.Code(t), "192.0.2.1:1"); w.Code != 200 {
		t.Fatal("new password after replacement", w.Code, w.Body)
	}
	audits, _, err := st.Audit().ListAuditRecords(ctx, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audits {
		if a.Action == "auth.password_changed" {
			found = true
		}
		if strings.Contains(a.Details, newPassword) || strings.Contains(a.Details, oldPassword) {
			t.Fatal("audit leaked password")
		}
	}
	if !found {
		t.Fatal("missing audit")
	}
}

func TestPasswordReplacementRequiresSessionAndPost(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	for _, tc := range []struct {
		method string
		want   int
	}{{http.MethodPost, 401}, {http.MethodGet, 405}} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(tc.method, "/api/auth/change-password", nil))
		if w.Code != tc.want {
			t.Fatal(w.Code)
		}
	}
}

// Simulate replacement committing after session lookup but before user lookup.
type resetDuringReadUsers struct {
	store.UserStore
	reset func()
}

func (u *resetDuringReadUsers) GetUserByID(ctx context.Context, id string) (*store.User, error) {
	if u.reset != nil {
		f := u.reset
		u.reset = nil
		f()
	}
	return u.UserStore.GetUserByID(ctx, id)
}

type resetDuringReadStore struct {
	store.Store
	users store.UserStore
}

func (s *resetDuringReadStore) Users() store.UserStore { return s.users }

func TestRestrictedSessionCannotInheritClearedFlag(t *testing.T) {
	_, st, cfg := setupTestServer(t)
	ctx := context.Background()
	u := &store.User{ID: "race", Username: "race", PasswordHash: "old", Status: "active", Role: "admin"}
	if err := st.MFA().CreateBreakGlass(ctx, u, &store.MFAFactor{ID: "mfa_race", SecretEnc: "sealed"}, &store.AuditRecord{Action: "break_glass.created"}); err != nil {
		t.Fatal(err)
	}
	u.MustChangePassword = true
	if err := st.Users().UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	manager := auth.NewSessionManager(st, cfg.Security)
	_, token, err := manager.IssueSession(ctx, httptest.NewRecorder(), httptest.NewRequest("POST", "/api/auth/login", nil), u)
	if err != nil {
		t.Fatal(err)
	}
	users := &resetDuringReadUsers{UserStore: st.Users(), reset: func() {
		if err := st.Users().CompletePasswordChange(ctx, u.ID, "old", "new", "127.0.0.1", "mfa_race"); err != nil {
			t.Fatal(err)
		}
	}}
	manager = auth.NewSessionManager(&resetDuringReadStore{Store: st, users: users}, cfg.Security)
	req := httptest.NewRequest("GET", "/api/backup/status", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, _, err := manager.AuthenticateRequest(req); err == nil {
		t.Fatal("revoked restricted session inherited full access")
	}
}

// A break-glass account changes its own password with the current one and a TOTP code; an
// SSO account has none to change.
func TestPasswordChangeForBreakGlassAccountsOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		sso  bool
		want int
	}{{"break-glass", false, 200}, {"federated", true, 409}} {
		t.Run(tc.name, func(t *testing.T) {
			srv, st, cfg := setupTestServer(t)
			ctx := context.Background()
			bg := newBreakGlass(t, srv, st, "user")
			u, err := st.Users().GetUserByID(ctx, bg.ID)
			if err != nil {
				t.Fatal(err)
			}
			if tc.sso {
				u = &store.User{ID: "usr_sso", Username: "sso", Status: "active", Role: "user", SSOProvider: "kysignon", SSOSubject: "s"}
				if err := st.Users().CreateUser(ctx, u); err != nil {
					t.Fatal(err)
				}
			}
			manager := auth.NewSessionManager(st, cfg.Security)
			_, token, err := manager.IssueSession(ctx, httptest.NewRecorder(), httptest.NewRequest("POST", "/api/auth/login", nil), u)
			if err != nil {
				t.Fatal(err)
			}
			b, _ := json.Marshal(map[string]string{"current_password": bg.Password, "new_password": "NewPassword-123456", "totp_code": bg.Code(t)})
			req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(string(b)))
			req.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != tc.want {
				t.Fatal(w.Code, w.Body)
			}
			if tc.want == 200 {
				me := httptest.NewRequest("GET", "/api/auth/me", nil)
				me.Header.Set("Authorization", "Bearer "+token)
				if _, _, err := manager.AuthenticateRequest(me); err == nil {
					t.Fatal("the session survived the password change")
				}
			}
		})
	}
}
