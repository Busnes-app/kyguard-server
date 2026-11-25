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

// §9.3 upgrade: records written before migration 15 carry no chain fields. The open that
// applies the migration chains them, so the next append and verification succeed. A row that
// shows up unchained afterwards (a writer without the key) is never signed: verification
// keeps reporting it.
func TestRecordsFromBeforeTheChainAreChainedOnce(t *testing.T) {
	ctx := context.Background()
	cfg := testdb.Config(t)
	st, err := store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	db, q := open(t, cfg)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q(query), args...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	unchained := func(action string) {
		t.Helper()
		exec(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`, "u", action, "r", "d\x01", "", time.Now().UTC())
	}
	_ = st.Close()
	// Back to the schema before migration 15, holding two records.
	exec(`DROP INDEX idx_audit_records_seq`)
	for _, col := range []string{"seq", "prev_hash", "hash"} {
		exec(`ALTER TABLE audit_records DROP COLUMN ` + col)
	}
	exec(`DROP TABLE audit_chain_head`)
	exec(`DELETE FROM schema_migrations WHERE version = 15`)
	exec(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`, "u", "legacy.one", "r", "d\x01", "", time.Now().UTC())
	exec(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`, "u", "legacy.two", "r", "d", "", time.Now().UTC())

	st, err = store.Open(ctx, cfg) // applies migration 15
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "after.upgrade"}); err != nil {
		t.Fatalf("append after the upgrade: %v", err)
	}
	if err := st.Audit().VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()

	unchained("forged.later")
	st, err = store.Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.Audit().VerifyAuditChain(ctx); !errors.Is(err, auditchain.ErrBrokenChain) {
		t.Fatalf("a row inserted unchained after the migration was signed: %v", err)
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
