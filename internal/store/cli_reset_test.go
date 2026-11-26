package store_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

// §7.6 with §7.3 rule 6: a factor reset racing a CLI code redemption never leaves the
// redeemed session behind (the race needs PostgreSQL).
func TestFactorResetRacingCLIRedemptionLeavesNoSession(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := &store.User{ID: "usr_clireset", Username: "clireset", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "clireset", SSOIssuer: "https://idp", AccountType: store.AccountSSO}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	now := func() time.Time { return time.Now().UTC() }
	for i := range 25 {
		p := &store.Session{TokenHash: fmt.Sprintf("p-%d", i), UserID: u.ID, CreatedAt: now(), ExpiresAt: now().Add(time.Minute), Stage: store.StagePending}
		if err := st.Sessions().CreateSession(ctx, p, ""); err != nil {
			t.Fatal(err)
		}
		if err := st.Sessions().ExchangeSession(ctx, p.TokenHash, "", &store.Session{TokenHash: fmt.Sprintf("a-%d", i), UserID: u.ID, CreatedAt: now(), ExpiresAt: now().Add(time.Hour)}, &store.MFAFactor{ID: fmt.Sprintf("f-%d", i), SecretEnc: "s"}); err != nil {
			t.Fatal(err)
		}
		code := &store.CLICode{CodeHash: fmt.Sprintf("c-%d", i), UserID: u.ID, SSOIssuer: "https://idp", SSOSID: "sid", IssuedAt: now(), Challenge: "x", ExpiresAt: now().Add(time.Minute)}
		if err := st.Sessions().CreateCLICode(ctx, code, &store.AuditRecord{Action: "test"}); err != nil {
			t.Fatal(err)
		}
		redeemed := &store.Session{TokenHash: fmt.Sprintf("cli-%d", i), UserID: u.ID, CreatedAt: now(), ExpiresAt: now().Add(time.Minute), Stage: store.StagePending}
		var wg sync.WaitGroup
		var redeemErr, resetErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			redeemErr = st.Sessions().RedeemCLICode(ctx, code.CodeHash, func(*store.CLICode) (*store.Session, error) { return redeemed, nil })
		}()
		go func() {
			defer wg.Done()
			resetErr = st.MFA().DeleteFactor(ctx, u.ID, &store.AuditRecord{Action: "admin.factor_reset"})
		}()
		wg.Wait()
		if resetErr != nil {
			t.Fatal(resetErr)
		}
		if redeemErr != nil && !errors.Is(redeemErr, store.ErrNotFound) {
			t.Fatal(redeemErr)
		}
		if _, err := st.Sessions().GetSession(ctx, redeemed.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: a CLI session survived the factor reset (redeem %v)", i, redeemErr)
		}
	}
}
