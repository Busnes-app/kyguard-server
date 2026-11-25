package backup

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/store"
)

// StaleIntent is how long a pending intent may still belong to a live request on another
// replica: longer than the longest detached backup action (16 minutes).
const StaleIntent = 20 * time.Minute

// ErrNotRecorded is an action whose effect happened but whose audit append failed. Its
// outcome stays on the intent and is appended when the intent is reconciled (spec §9.3).
var ErrNotRecorded = errors.New("backup: outcome not recorded in the audit log")

// ReconcileIntents settles intents a stopped process left; startup calls it before serving.
// No deposit runs while this holds the backup-run lock, so every pending deposit is settled;
// a pairing or pin may still be a live request on another replica until it is StaleIntent old.
func ReconcileIntents(ctx context.Context, st store.Store) error {
	reconcile := func(ctx context.Context, kind string, olderThan time.Duration) error {
		n, err := st.Intents().Reconcile(ctx, kind, olderThan)
		if err != nil {
			return fmt.Errorf("reconcile %s intents: %w", kind, err)
		}
		if n > 0 {
			log.Printf("[BACKUP] reconciled %d %s intents left by a stopped process", n, kind)
		}
		return nil
	}
	if err := ReconcileStale(ctx, st); err != nil {
		return err
	}
	// Lost to a running backup: that run reconciles under the lock itself (Run).
	_, err := st.Coordination().WithLock(ctx, "backup-run", func(owned context.Context) error {
		return reconcile(owned, "deposit", 0)
	})
	return err
}

// ReconcileStale settles pairing and pin intents pending for StaleIntent: a process that died
// on them is gone by then. Startup and every scheduled-worker tick call it, so an intent too
// young to settle at startup is settled later without waiting for another such request.
func ReconcileStale(ctx context.Context, st store.Store) error {
	for _, kind := range []string{"pairing", "pin"} {
		n, err := st.Intents().Reconcile(ctx, kind, StaleIntent)
		if err != nil {
			return fmt.Errorf("reconcile %s intents: %w", kind, err)
		}
		if n > 0 {
			log.Printf("[BACKUP] reconciled %d %s intents left by a stopped process", n, kind)
		}
	}
	return nil
}

// BeginIntent reconciles kind's stale intents, then commits a new pending one, before the
// effect is attempted again.
func BeginIntent(ctx context.Context, st store.Store, kind, subject string) (string, error) {
	ctx = context.WithoutCancel(ctx)
	if _, err := st.Intents().Reconcile(ctx, kind, StaleIntent); err != nil {
		return "", fmt.Errorf("backup: reconcile earlier %s intents: %w", kind, err)
	}
	return st.Intents().Begin(ctx, kind, subject)
}

// SettleIntent ends an intent with r as its completion append. ErrNotRecorded when the
// append failed: the action fails, and Reconcile appends the noted record later.
func SettleIntent(ctx context.Context, st store.Store, operationID, state string, r *store.AuditRecord) error {
	err := st.Intents().Settle(context.WithoutCancel(ctx), operationID, state, r)
	if err == nil || errors.Is(err, store.ErrNotFound) { // ErrNotFound: reconciled from its note meanwhile
		return nil
	}
	return fmt.Errorf("%w: %w", ErrNotRecorded, err)
}
