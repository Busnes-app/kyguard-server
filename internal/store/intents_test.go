package store_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

func intentsStore(t *testing.T) (store.Store, func(string, ...any)) {
	t.Helper()
	cfg := testdb.Config(t)
	st, err := store.Open(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	db, q := open(t, cfg)
	return st, func(query string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q(query), args...); err != nil {
			t.Fatal(err)
		}
	}
}

func intentState(t *testing.T, st store.Store, id string) string {
	t.Helper()
	in, err := st.Intents().Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return in.State
}

// lastActions lists the audit actions, newest first.
func lastActions(t *testing.T, st store.Store) []string {
	t.Helper()
	recs, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.Action)
	}
	return out
}

// Acceptance 12 (external effects): an effect whose process died before its completion
// append leaves a pending intent; reconciliation ends it outcome_unknown with an audit
// record, and the next successful deposit supersedes it. A young intent is left alone.
func TestReconcileEndsLostDepositsAndASuccessSupersedesThem(t *testing.T) {
	st, _ := intentsStore(t)
	ctx := context.Background()
	lost, err := st.Intents().Begin(ctx, "deposit", "kyguard")
	if err != nil {
		t.Fatal(err)
	}
	if n, err := st.Intents().Reconcile(ctx, "deposit", time.Hour); err != nil || n != 0 {
		t.Fatalf("a young intent was reconciled: %d %v", n, err)
	}
	if n, err := st.Intents().Reconcile(ctx, "deposit", 0); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if got := intentState(t, st, lost); got != store.IntentUnknown {
		t.Fatalf("lost deposit is %s", got)
	}
	if got := lastActions(t, st); len(got) == 0 || got[0] != "operation.outcome_unknown" {
		t.Fatalf("no outcome_unknown audit record: %v", got)
	}
	next, err := st.Intents().Begin(ctx, "deposit", "kyguard")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Intents().Settle(ctx, next, store.IntentComplete, &store.AuditRecord{UserID: "system", Action: "backup.deposited"}); err != nil {
		t.Fatal(err)
	}
	if got := intentState(t, st, lost); got != store.IntentSuperseded {
		t.Fatalf("after a later deposit the lost one is %s, want superseded", got)
	}
	if got := intentState(t, st, next); got != store.IntentComplete {
		t.Fatalf("the deposit is %s", got)
	}
}

// §9.3: the completion append and the intent's end commit together. When the append fails,
// the intent stays pending with its outcome noted, and reconciliation appends that record.
func TestFailedCompletionAppendIsReplayedFromTheIntent(t *testing.T) {
	st, exec := intentsStore(t)
	ctx := context.Background()
	if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	id, err := st.Intents().Begin(ctx, "pin", "key-1")
	if err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE audit_chain_head SET head_hash = '` + strings.Repeat("f", 64) + `'`)
	if err := st.Intents().Settle(ctx, id, store.IntentComplete, &store.AuditRecord{UserID: "usr_admin", Action: "admin.backup_key_pin", Resource: "key-1"}); err == nil {
		t.Fatal("settle with a broken chain succeeded")
	}
	if got := intentState(t, st, id); got != store.IntentPending {
		t.Fatalf("the intent ended without its record: %s", got)
	}
	// An operator restores the chain (here: from genesis), then the intent is reconciled.
	exec(`DELETE FROM audit_chain_head`)
	exec(`DELETE FROM audit_records`)
	if n, err := st.Intents().Reconcile(ctx, "pin", 0); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if got := intentState(t, st, id); got != store.IntentComplete {
		t.Fatalf("reconciled to %s, want the noted complete", got)
	}
	if got := lastActions(t, st); len(got) != 1 || got[0] != "admin.backup_key_pin" {
		t.Fatalf("replayed records %v, want the noted admin.backup_key_pin", got)
	}
	if err := st.Audit().VerifyAuditChain(ctx); err != nil {
		t.Fatal(err)
	}
}

// A settled intent cannot be settled again, so a late answer never writes a second record.
func TestSettledIntentStaysSettled(t *testing.T) {
	st, _ := intentsStore(t)
	ctx := context.Background()
	id, err := st.Intents().Begin(ctx, "pairing", "https://recovery.test")
	if err != nil {
		t.Fatal(err)
	}
	rec := func() *store.AuditRecord { return &store.AuditRecord{UserID: "u", Action: "backup.paired"} }
	if err := st.Intents().Settle(ctx, id, store.IntentComplete, rec()); err != nil {
		t.Fatal(err)
	}
	if err := st.Intents().Settle(ctx, id, store.IntentFailed, rec()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second settle: %v", err)
	}
	if got := lastActions(t, st); len(got) != 1 {
		t.Fatalf("records %v", got)
	}
}

// §9.3: reconciliation replays only an outcome this server noted. A note a database writer
// without the key edited, or wrote, is rejected: its record is never appended, and the intent
// ends outcome_unknown with the rejection on record.
func TestReconcileRejectsAForgedNote(t *testing.T) {
	for _, forge := range []struct{ name, query string }{
		{"edited", `UPDATE operation_intents SET outcome = REPLACE(outcome, 'admin.backup_key_pin', 'forged.event')`},
		{"written", `UPDATE operation_intents SET outcome = '{"state":"complete","record":{"Action":"forged.event"},"mac":"00"}'`},
	} {
		t.Run(forge.name, func(t *testing.T) {
			st, exec := intentsStore(t)
			ctx := context.Background()
			if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "seed"}); err != nil {
				t.Fatal(err)
			}
			id, err := st.Intents().Begin(ctx, "pin", "key-1")
			if err != nil {
				t.Fatal(err)
			}
			exec(`UPDATE audit_chain_head SET head_hash = '` + strings.Repeat("f", 64) + `'`)
			if err := st.Intents().Settle(ctx, id, store.IntentComplete, &store.AuditRecord{UserID: "usr_admin", Action: "admin.backup_key_pin"}); err == nil {
				t.Fatal("settle with a broken chain succeeded")
			}
			exec(`DELETE FROM audit_chain_head`)
			exec(`DELETE FROM audit_records`)
			exec(forge.query)
			if _, err := st.Intents().Reconcile(ctx, "pin", 0); err != nil {
				t.Fatal(err)
			}
			if got := intentState(t, st, id); got != store.IntentUnknown {
				t.Fatalf("forged note reconciled to %s", got)
			}
			if got := lastActions(t, st); len(got) != 1 || got[0] != "operation.outcome_rejected" {
				t.Fatalf("records %v, want only the rejection", got)
			}
		})
	}
}

// §9.3: two replicas reconciling the same stale intents append one record per intent.
func TestConcurrentReconcilersSettleOnce(t *testing.T) {
	st, _ := intentsStore(t)
	ctx := context.Background()
	const intents = 10
	for range intents {
		if _, err := st.Intents().Begin(ctx, "pairing", "https://recovery.test"); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := st.Intents().Reconcile(ctx, "pairing", 0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	n := 0
	for _, a := range lastActions(t, st) {
		if a == "operation.outcome_unknown" {
			n++
		}
	}
	if n != intents {
		t.Fatalf("%d outcome records for %d intents", n, intents)
	}
}

// A reconciler that read an empty note before Settle noted the outcome must not end the
// intent outcome_unknown: the note stays replayable even when Settle's own append then fails.
func TestReconcilerDoesNotStrandANoteWrittenAfterItsRead(t *testing.T) {
	st, exec := intentsStore(t)
	ctx := context.Background()
	if err := st.Audit().LogAudit(ctx, &store.AuditRecord{Action: "seed"}); err != nil {
		t.Fatal(err)
	}
	id, err := st.Intents().Begin(ctx, "pairing", "kyrecovery")
	if err != nil {
		t.Fatal(err)
	}
	// The owner notes its outcome, then its append fails.
	exec(`UPDATE audit_chain_head SET head_hash = '` + strings.Repeat("f", 64) + `'`)
	if err := st.Intents().Settle(ctx, id, store.IntentComplete, &store.AuditRecord{UserID: "usr_admin", Action: "admin.backup_pair", Resource: "kyrecovery"}); err == nil {
		t.Fatal("settle with a broken chain succeeded")
	}
	exec(`DELETE FROM audit_chain_head`)
	exec(`DELETE FROM audit_records`)
	// The reconciler read the intent before the note existed.
	err = store.SettleAsReconciler(st, ctx, id, "", store.IntentUnknown, &store.AuditRecord{UserID: "system", Action: "operation.outcome_unknown"})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("stale reconciler settled a noted intent: %v", err)
	}
	if got := intentState(t, st, id); got != store.IntentPending {
		t.Fatalf("intent is %s, want pending", got)
	}
	if n, err := st.Intents().Reconcile(ctx, "pairing", 0); err != nil || n != 1 {
		t.Fatalf("reconcile: %d %v", n, err)
	}
	if got := lastActions(t, st); len(got) != 1 || got[0] != "admin.backup_pair" {
		t.Fatalf("records %v, want the noted admin.backup_pair", got)
	}
}
