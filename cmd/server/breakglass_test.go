package main

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/totp"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

type testBreakGlass struct {
	ID, Password, Secret, Hash string
	used                       int
}

// Code returns an unspent code: the current step, then the next (both survive a boundary).
func (b *testBreakGlass) Code(t *testing.T) string {
	t.Helper()
	if b.used >= 2 {
		t.Fatal("a third code inside 30 s; use another account")
	}
	code, err := totp.Code(b.Secret, time.Now().Add(time.Duration(b.used)*totp.Period*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	b.used++
	return code
}

var printed = regexp.MustCompile(`(?m)^Password: (\S+)\nTOTP: (\S+)$`)

// newTestBreakGlass runs the host command and reads back what it printed.
func newTestBreakGlass(t *testing.T, cfg *config.Config, st store.Store, username string) *testBreakGlass {
	t.Helper()
	ctx := context.Background()
	var out bytes.Buffer
	if err := createBreakGlass(ctx, cfg, st, username, &out); err != nil {
		t.Fatal(err)
	}
	m := printed.FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("break-glass create printed %q", out.String())
	}
	uri, err := url.Parse(m[2])
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.Users().GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatal(err)
	}
	return &testBreakGlass{ID: u.ID, Password: m[1], Secret: uri.Query().Get("secret"), Hash: u.PasswordHash}
}

// §7.4: break-glass accounts are created and reset only on the host, at most five exist, and an
// empty database has no admin (acceptance 9).
func TestBreakGlassHostCommands(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KY_DATA_DIR", t.TempDir())
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = testdb.Config(t) // both drivers
	st := openStore(t, cfg)
	if err := bootstrap(ctx, cfg, st); err != nil {
		t.Fatal(err)
	}
	if n, err := st.Users().CountUsers(ctx); err != nil || n != 0 {
		t.Fatalf("an empty database started with %d accounts (%v)", n, err)
	}
	first := newTestBreakGlass(t, cfg, st, "bg1")
	u, err := st.Users().GetUserByID(ctx, first.ID)
	if err != nil || u.AccountType != store.AccountBreakGlass || u.Role != "admin" || len(first.Password) < 16 {
		t.Fatalf("created %+v (%v), password %d chars", u, err, len(first.Password))
	}
	if err := createBreakGlass(ctx, cfg, st, "bg1", &bytes.Buffer{}); err == nil {
		t.Fatal("a second account took an existing name")
	}
	for i := 2; i <= store.MaxBreakGlass; i++ {
		newTestBreakGlass(t, cfg, st, "bg"+strconv.Itoa(i))
	}
	if err := createBreakGlass(ctx, cfg, st, "bg6", &bytes.Buffer{}); !errors.Is(err, store.ErrBreakGlassLimit) {
		t.Fatalf("sixth break-glass account: %v", err)
	}

	if err := st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "live", UserID: first.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, first.Hash); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := resetBreakGlassTOTP(ctx, cfg, st, "bg1", &out); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Sessions().GetSession(ctx, "live"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("reset left the session: %v", err)
	}
	factors, err := auth.NewFactors(st, cfg.Security.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factors.Check(ctx, first.ID, "", first.Code(t)); !errors.Is(err, auth.ErrCodeRejected) {
		t.Fatalf("the replaced secret still verifies: %v", err)
	}
	if !strings.Contains(out.String(), "otpauth://totp/") {
		t.Fatalf("reset printed %q", out.String())
	}

	if err := st.Users().CreateUser(ctx, &store.User{ID: "usr_sso", Username: "sso", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "s"}); err != nil {
		t.Fatal(err)
	}
	if err := resetBreakGlassTOTP(ctx, cfg, st, "sso", &bytes.Buffer{}); err == nil {
		t.Fatal("reset-totp touched an SSO account")
	}
}
