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

// §7.3 rule 6: a factor reset racing an exchange authorized by the old factor never leaves a
// usable session behind a successful reset (both drivers; the race needs PostgreSQL).
func TestFactorResetRacingAnExchangeLeavesNoSession(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := &store.User{ID: "usr_reset", Username: "reset", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "reset", SSOIssuer: "https://idp", AccountType: store.AccountSSO}
	if err := st.Users().CreateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	pending := func(name string) *store.Session {
		p := &store.Session{TokenHash: name, UserID: u.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Minute), Stage: store.StagePending}
		if err := st.Sessions().CreateSession(ctx, p, ""); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for i := range 25 {
		factor := &store.MFAFactor{ID: fmt.Sprintf("f-%d", i), SecretEnc: "sealed"}
		enrolled := &store.Session{TokenHash: fmt.Sprintf("enrolled-%d", i), UserID: u.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour)}
		if err := st.Sessions().ExchangeSession(ctx, pending(fmt.Sprintf("p0-%d", i)).TokenHash, "", enrolled, factor); err != nil {
			t.Fatal(err)
		}
		p := pending(fmt.Sprintf("p-%d", i))
		active := &store.Session{TokenHash: fmt.Sprintf("active-%d", i), UserID: u.ID, CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), FactorID: factor.ID}
		var wg sync.WaitGroup
		var exchangeErr, resetErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			exchangeErr = st.Sessions().ExchangeSession(ctx, p.TokenHash, "", active, nil)
		}()
		go func() {
			defer wg.Done()
			resetErr = st.MFA().DeleteFactor(ctx, u.ID, &store.AuditRecord{Action: "admin.factor_reset"})
		}()
		wg.Wait()
		if resetErr != nil {
			t.Fatal(resetErr)
		}
		if exchangeErr != nil && !errors.Is(exchangeErr, store.ErrNotFound) {
			t.Fatal(exchangeErr)
		}
		if _, err := st.Sessions().GetSession(ctx, active.TokenHash); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("round %d: a session from the old factor survived the reset (exchange %v)", i, exchangeErr)
		}
	}
}
