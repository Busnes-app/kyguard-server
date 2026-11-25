package api_test

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/crypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Acceptance 11: every main-mux route goes through the registry with a class. Source outside
// routes.go may not call Handle or HandleFunc on a mux, and the registry refuses a missing class.
func TestEveryRouteIsClassified(t *testing.T) {
	for _, dir := range []string{".", "../scim"} {
		files, _ := filepath.Glob(filepath.Join(dir, "*.go"))
		for _, path := range files {
			if strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "routes.go" {
				continue
			}
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if sel, ok := n.(*ast.SelectorExpr); ok && (sel.Sel.Name == "HandleFunc" || sel.Sel.Name == "Handle") {
					t.Errorf("%s registers a route outside the registry (%s)", path, sel.Sel.Name)
				}
				return true
			})
		}
	}
	srv, _, _ := setupTestServer(t)
	seen := map[string]api.RouteClass{}
	for _, r := range srv.Routes() {
		if r.Class == "" {
			t.Errorf("%s has no class", r.Pattern)
		}
		seen[r.Pattern] = r.Class
	}
	// The spec §7.5 table, for the routes it names.
	for pattern, want := range map[string]api.RouteClass{
		"GET /livez": api.ClassPublic, "GET /readyz": api.ClassPublic, "/": api.ClassPublic,
		"/api/settings": api.ClassPublic, "/api/auth/pow-challenge": api.ClassPublic, "/api/auth/login": api.ClassPublic,
		"/api/sso/kysignon/login": api.ClassPublic, "/api/sso/oidc/login": api.ClassPublic,
		"/api/sso/kysignon/callback": api.ClassPublic, "/api/sso/oidc/callback": api.ClassPublic,
		"POST /api/sso/kysignon/backchannel-logout": api.ClassMachine, "/scim/v2/": api.ClassMachine,
		"/api/auth/me": api.ClassPending, "/api/auth/logout": api.ClassPending, "POST /api/auth/stepup/totp": api.ClassPending,
		"POST /api/auth/change-password": api.ClassSession, "GET /api/admin/users": api.ClassSession,
	} {
		if seen[pattern] != want {
			t.Errorf("%s: class %q, want %q", pattern, seen[pattern], want)
		}
	}
}

// Acceptance 11: registering without a class fails.
func TestRouteWithoutAClassPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a route without a class was registered")
		}
	}()
	srv, _, _ := setupTestServer(t)
	api.RegisterForTest(srv, "", "/x")
}

// Acceptance 4: every session-class route refuses anonymous callers and pending sessions,
// by cookie and by Bearer.
func TestSessionRoutesRefusePendingSessions(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	ctx := context.Background()
	u := &store.User{ID: "usr_p", Username: "pend", Role: "admin", Status: "active", SSOProvider: "kysignon", SSOSubject: "p", SSOIssuer: "https://idp"}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	raw := crypto.RandomHex(32)
	now := time.Now().UTC()
	if err := st.Sessions().CreateSession(ctx, &store.Session{TokenHash: crypto.SHA256Hex([]byte(raw)), UserID: u.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute), Stage: store.StagePending}, ""); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range srv.Routes() {
		if r.Class != api.ClassSession {
			continue
		}
		n++
		method, path, found := strings.Cut(r.Pattern, " ")
		if !found {
			method, path = http.MethodGet, r.Pattern
		}
		path = strings.ReplaceAll(path, "{id}", "usr_p")
		for _, c := range []struct {
			name string
			set  func(*http.Request)
			want int
		}{
			{"anonymous", func(*http.Request) {}, http.StatusUnauthorized},
			{"pending cookie", func(q *http.Request) { q.AddCookie(&http.Cookie{Name: "ky_session", Value: raw}) }, http.StatusForbidden},
			{"pending bearer", func(q *http.Request) { q.Header.Set("Authorization", "Bearer "+raw) }, http.StatusForbidden},
		} {
			req := httptest.NewRequest(method, path, strings.NewReader("{}"))
			c.set(req)
			req.AddCookie(&http.Cookie{Name: "ky_csrf", Value: "c"})
			req.Header.Set("X-CSRF-Token", "c")
			w := httptest.NewRecorder()
			srv.ServeHTTP(w, req)
			if w.Code != c.want {
				t.Errorf("%s %s (%s): %d, want %d", method, path, c.name, w.Code, c.want)
			}
		}
	}
	if n < 10 {
		t.Fatalf("only %d session routes", n)
	}
}

// §7.3 rule 6: backup actions need a step-up within five minutes; a new code refreshes it.
func TestBackupActionsNeedAFreshStepUp(t *testing.T) {
	srv, st, cfg := setupTestServer(t)
	bg := newBreakGlass(t, srv, st, "root")
	cookie := bg.Login(t, srv)
	db, err := sql.Open(map[string]string{"sqlite": "sqlite", "postgres": "pgx"}[cfg.Database.Driver], cfg.Database.DSN)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	q := "UPDATE sessions SET stepup_at = ? WHERE token_hash = ?"
	if cfg.Database.Driver == "postgres" {
		q = "UPDATE sessions SET stepup_at = $1 WHERE token_hash = $2"
	}
	if _, err := db.Exec(q, time.Now().UTC().Add(-6*time.Minute), crypto.SHA256Hex([]byte(cookie.Value))); err != nil {
		t.Fatal(err)
	}
	if w := do(t, srv, "PUT", "/api/backup/schedule", cookie); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "stepup_stale") {
		t.Fatalf("stale step-up: %d %s", w.Code, w.Body)
	}
	if w := post(srv, cookie, "/api/auth/stepup/totp", map[string]string{"code": bg.Code(t)}); w.Code != http.StatusOK {
		t.Fatalf("re-step-up: %d %s", w.Code, w.Body)
	}
	if w := do(t, srv, "PUT", "/api/backup/schedule", cookie); w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
		t.Fatalf("fresh step-up still refused: %d %s", w.Code, w.Body)
	}
}

// §7.3 rule 6: an admin resets an SSO user's factor only with a fresh code of their own; the
// user's sessions end. Break-glass factors are not reachable here.
func TestAdminFactorResetNeedsAFreshCode(t *testing.T) {
	srv, st, f := ssoServer(t)
	ctx := context.Background()
	_, userSession := enroll(t, srv, pending(t, srv, f, "gus", "sid-1", map[string]any{"amr": []string{"mfa"}}))
	gus, err := st.Users().GetUserBySSO(ctx, f.issuer, "gus")
	if err != nil {
		t.Fatal(err)
	}
	admin := newBreakGlass(t, srv, st, "root")
	cookie := admin.Login(t, srv)
	del := func(id, code string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodDelete, "/api/admin/users/"+id+"/factor", strings.NewReader(`{"code":"`+code+`"}`))
		req.AddCookie(cookie)
		req.AddCookie(&http.Cookie{Name: "ky_csrf", Value: "c"})
		req.Header.Set("X-CSRF-Token", "c")
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		return w
	}
	if w := del(gus.ID, "000000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("reset with a wrong code: %d", w.Code)
	}
	if w := del(admin.ID, admin.Code(t)); w.Code != http.StatusNotFound {
		t.Fatalf("break-glass factor reset over the web: %d", w.Code)
	}
	newAdmin := newBreakGlass(t, srv, st, "root2")
	cookie = newAdmin.Login(t, srv)
	if w := del(gus.ID, newAdmin.Code(t)); w.Code != http.StatusOK {
		t.Fatalf("reset: %d %s", w.Code, w.Body)
	}
	if _, err := st.MFA().GetFactor(ctx, gus.ID, store.FactorTOTP); err != store.ErrNotFound || signedIn(srv, userSession) {
		t.Fatalf("factor %v, session kept %v", err, signedIn(srv, userSession))
	}
}
