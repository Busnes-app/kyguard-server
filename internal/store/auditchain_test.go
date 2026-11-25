package store_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Busnes-app/ky-primitives/auditchain"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

// Acceptance 12: concurrent writers appending from an empty log, and again from a non-empty
// one, produce one gap-free chain that verifies against its head (both drivers). Writers
// start together on a barrier, on several fresh logs, so the genesis race is exercised.
func TestConcurrentAuditWritersMakeOneChain(t *testing.T) {
	ctx := context.Background()
	const writers = 50
	for log := range 5 {
		st := newTestStore(t)
		if err := st.Audit().VerifyAuditChain(ctx); err != nil {
			t.Fatalf("empty log against the zero anchor: %v", err)
		}
		for round := range 2 { // round 0 starts at genesis, round 1 from a non-empty log
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make(chan error, writers)
			for i := range writers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					errs <- st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "test.concurrent", Details: fmt.Sprintf("log=%d round=%d writer=%d", log, round, i)})
				}()
			}
			close(start)
			wg.Wait()
			close(errs)
			for err := range errs {
				if err != nil {
					t.Fatalf("log %d round %d: %v", log, round, err)
				}
			}
			if err := st.Audit().VerifyAuditChain(ctx); err != nil {
				t.Fatalf("log %d round %d: %v", log, round, err)
			}
		}
		if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 1); err != nil || n != 2*writers {
			t.Fatalf("log %d: %d records (%v)", log, n, err)
		}
	}
}

// Acceptance 12: a password change audits through the chain (revokePasswordGrants), and an
// edited or truncated log no longer verifies.
func TestAuditChainCoversPasswordChangesAndDetectsTampering(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	u := &store.User{ID: "pw", Username: "pw", PasswordHash: "old", Role: "admin", Status: "active"}
	factor := breakGlassUser(t, st, u)
	if err := st.Users().CompletePasswordChange(ctx, u.ID, "old", "new", "", factor); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	db, q := open(t, cfg)
	if _, err := db.Exec(q("UPDATE audit_records SET details = 'edited' WHERE action = ?"), "auth.password_changed"); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("an edited record verified: %v", err)
	}
	if _, err := db.Exec("DELETE FROM audit_records WHERE seq = (SELECT MAX(seq) FROM audit_records)"); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); err == nil {
		t.Fatal("a truncated log verified against its head")
	}
}

// Acceptance 12: a failed audit write rolls back the database-only action with it.
func TestFailedAuditRollsBackTheAction(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	db, _ := open(t, cfg)
	if _, err := db.Exec("UPDATE audit_chain_head SET head_hash = '" + strings.Repeat("f", 64) + "'"); err != nil {
		t.Fatal(err)
	}
	u := &store.User{ID: "bg", Username: "bg-one", PasswordHash: "h", Role: "admin", Status: "active"}
	err = st.MFA().CreateBreakGlass(ctx, u, &store.MFAFactor{ID: "f", SecretEnc: "s"}, &store.AuditRecord{Action: "break_glass.created"})
	if !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("create with a broken chain: %v", err)
	}
	if _, err := st.Users().GetUserByID(ctx, "bg"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("the account survived its failed audit write: %v", err)
	}
}

// §9.3: no audit write without the chain key.
func TestAuditWriteNeedsTheChainKey(t *testing.T) {
	cfg := testdb.Config(t)
	cfg.AuditKey = nil
	st, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Audit().LogAudit(context.Background(), &store.AuditRecord{Action: "x"}); err == nil {
		t.Fatal("an audit record was written without the chain key")
	}
}

// open returns a raw handle on the test database and a ? to $n rewriter for PostgreSQL.
func open(t *testing.T, cfg config.DatabaseConfig) (*sql.DB, func(string) string) {
	t.Helper()
	name := map[string]string{"sqlite": "sqlite", "postgres": "pgx"}[cfg.Driver]
	db, err := sql.Open(name, cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, func(q string) string {
		if cfg.Driver != "postgres" {
			return q
		}
		for i := 1; strings.Contains(q, "?"); i++ {
			q = strings.Replace(q, "?", "$"+strconv.Itoa(i), 1)
		}
		return q
	}
}
