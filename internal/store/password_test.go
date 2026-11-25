package store_test

import (
	"context"
	"errors"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"sync"
	"testing"
	"time"
)

func TestPasswordReplacementIsAtomicAndSingleUse(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u := &store.User{ID: "reset", Username: "reset", PasswordHash: "old", Role: "admin", Status: "active"}
	factor := breakGlassUser(t, st, u)
	sess := &store.Session{TokenHash: "session", UserID: u.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}
	if err := st.Sessions().CreateSession(ctx, sess, "old"); err != nil {
		t.Fatal(err)
	}
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for _, hash := range []string{"new-one", "new-two"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- st.Users().CompletePasswordChange(ctx, u.ID, "old", hash, "127.0.0.1", factor)
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("%d successful changes", success)
	}
	if _, err := st.Sessions().GetSession(ctx, sess.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("session survived", err)
	}
	if err := st.Sessions().CreateSession(ctx, sess, "old"); !errors.Is(err, store.ErrNotFound) {
		t.Fatal("stale session creation", err)
	}
	audits, n, err := st.Audit().ListAuditRecords(ctx, 0, 10)
	if err != nil || n != 2 || audits[0].Action != "auth.password_changed" { // newest first; the other is the creation
		t.Fatal("audit", n, err)
	}
}

// A directory sync works from a read taken before a concurrent reset; its write must not put
// the old password hash back.
func TestUpdateUserProfileLeavesCredentialsAlone(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u := &store.User{ID: "sync", Username: "sync", PasswordHash: "old", Role: "admin", Status: "active"}
	factor := breakGlassUser(t, st, u)
	stale, err := st.Users().GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Users().CompletePasswordChange(ctx, u.ID, "old", "reset-hash", "", factor); err != nil {
		t.Fatal(err)
	}
	stale.DisplayName = "Synced Name"
	if err := st.Users().UpdateUserProfile(ctx, stale, stale.Role, stale.Status); err != nil {
		t.Fatal(err)
	}
	got, err := st.Users().GetUserByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DisplayName != "Synced Name" {
		t.Fatalf("profile not written: %+v", got)
	}
	if got.PasswordHash != "reset-hash" {
		t.Fatalf("stale profile write restored credentials: hash=%q", got.PasswordHash)
	}
	if err := st.Users().UpdateUserProfile(ctx, &store.User{ID: "missing"}, "", ""); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
}

// breakGlassUser creates u as a break-glass account with a factor and returns the factor ID.
func breakGlassUser(t *testing.T, st store.Store, u *store.User) string {
	t.Helper()
	f := &store.MFAFactor{ID: "mfa_" + u.ID, SecretEnc: "sealed"}
	if err := st.MFA().CreateBreakGlass(context.Background(), u, f, &store.AuditRecord{Action: "break_glass.created"}); err != nil {
		t.Fatal(err)
	}
	return f.ID
}

// A host TOTP reset that lands between a password change's code check and its write wins: the
// change, authorized by the replaced factor, is refused and the hash stays.
func TestPasswordChangeIsFencedByATOTPReset(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	u := &store.User{ID: "pw", Username: "pw", PasswordHash: "old", Role: "admin", Status: "active"}
	factor := breakGlassUser(t, st, u)
	if err := st.MFA().ReplaceFactor(ctx, u.ID, "mfa_new", "sealed2", &store.AuditRecord{Action: "break_glass.totp_reset"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Users().CompletePasswordChange(ctx, u.ID, "old", "attacker-hash", "", factor); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("change authorized by a replaced factor: %v", err)
	}
	if got, _ := st.Users().GetUserByID(ctx, u.ID); got.PasswordHash != "old" {
		t.Fatalf("password replaced to %q", got.PasswordHash)
	}
}
