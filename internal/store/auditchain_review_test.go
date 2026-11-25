package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/auditchain"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

// §9.3: the HMAC covers each field's canonical rendering, so a stored value that renders the
// same but differs (text past the bound, appended by a writer without the key) breaks the
// chain instead of verifying and being shown as written.
func TestNoncanonicalStoredFieldBreaksTheChain(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "long", Details: strings.Repeat("a", 400)}); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	db, q := open(t, cfg)
	if _, err := db.Exec(q(`UPDATE audit_records SET details = details || ?`), " (and the attacker's text)"); err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("noncanonical details verified: %v", err)
	}
}

// §9.3 upgrade: records written before migration 15 carry no chain fields. Opening the store
// chains them, after any chained ones, so the next append and verification succeed.
func TestRecordsFromBeforeTheChainAreChainedAtOpen(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	db, q := open(t, cfg)
	legacy := func(action string) {
		t.Helper()
		if _, err := db.Exec(q(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
			"u", action, "r", "d\x01", "", time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
	legacy("legacy.one")
	legacy("legacy.two")
	if err := st.Audit().VerifyAuditChain(ctx); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("a log with unchained records verified: %v", err)
	}
	_ = st.Close()
	for round, action := range []string{"after.genesis", "after.chained"} {
		st, err = store.Open(ctx, cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: action}); err != nil {
			t.Fatalf("round %d: append after the upgrade: %v", round, err)
		}
		if err := st.Audit().VerifyAuditChain(ctx); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		_ = st.Close()
		legacy("legacy.late") // an old binary wrote more; the next open chains it after the head
	}
	st, err = store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Audit().VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, n, err := st.Audit().ListAuditRecords(ctx, 0, 10); err != nil || n != 6 {
		t.Fatalf("%d records (%v), want 6", n, err)
	}
}

// §9.3: verification reads the head and the records in one snapshot, so it passes while
// writers append (the race needs PostgreSQL at read committed).
func TestVerifyWhileWritersAppend(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "busy"}); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	for i := range 40 {
		if err := st.Audit().VerifyAuditChain(ctx); err != nil {
			close(stop)
			wg.Wait()
			t.Fatalf("verification %d during appends: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()
}
