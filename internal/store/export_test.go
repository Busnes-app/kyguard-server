package store

import "context"

// SettleAsReconciler is Reconcile's settle of a pending intent whose note it read as outcome.
func SettleAsReconciler(st Store, ctx context.Context, id, outcome, state string, r *AuditRecord) error {
	return st.Intents().(*intentStore).settle(ctx, id, state, r, &outcome, IntentPending)
}
