package backup

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// lastAttemptKey is the row recoveryclient.Run stamps before it works and NextRun counts from.
// The lib does not export it; TestInterruptedRunIsDueAgain fails if the two drift apart.
const lastAttemptKey = "backup_last_attempt"

// ErrInterrupted marks a run cut short because the server is stopping.
var ErrInterrupted = errors.New("backup: interrupted by shutdown")

// Recorder builds a run's audit record. A nil Recorder, or a nil record, writes none unless
// the run reached a deposit, which is always recorded.
type Recorder func(recoveryclient.Result, error) *store.AuditRecord

// Run is recoveryclient.Run for a process that may be told to stop mid-run, recorded by
// record. Callers hold the backup-run lock, so a deposit intent still pending is a dead
// run's: it is reconciled before this run deposits again (spec §9.3). A run that will
// deposit commits its intent after collecting, before sealing; the run's audit record is the
// intent's completion append, and a failed append fails the run with ErrNotRecorded.
func Run(ctx context.Context, cfg *config.Config, rc recoveryclient.RunConfig, st store.Store, client recoveryclient.Depositor, record Recorder) (recoveryclient.Result, error) {
	if _, err := st.Intents().Reconcile(context.WithoutCancel(ctx), "deposit", 0); err != nil {
		return recoveryclient.Result{}, fmt.Errorf("%w: reconcile earlier deposits: %w", ErrNotRecorded, err)
	}
	var intent string
	res, err := run(ctx, cfg, rc, st, client, &intent)
	var rec *store.AuditRecord
	if record != nil {
		rec = record(res, err)
	}
	switch {
	case intent != "":
		state := store.IntentUnknown // the deposit may have reached KyRecovery
		if res.Receipt != nil || err == nil {
			state = store.IntentComplete
		}
		if rec == nil {
			action, outcome, _ := recoveryclient.Outcome(res, err)
			rec = &store.AuditRecord{UserID: "system", Action: action, Resource: res.Manifest.CapsuleID, Details: "outcome=" + outcome}
		}
		if serr := SettleIntent(ctx, st, intent, state, rec); serr != nil {
			return res, errors.Join(err, serr)
		}
	case rec != nil:
		if aerr := st.Audit().LogAudit(context.WithoutCancel(ctx), rec); aerr != nil {
			return res, errors.Join(err, fmt.Errorf("%w: %w", ErrNotRecorded, aerr))
		}
	}
	return res, err
}

// run is one unrecorded run. Cancelling ctx aborts the snapshot and the upload. The settings
// writes ignore the cancellation, so a receipt KyRecovery has already returned is still
// recorded. An interrupted run gives its attempt stamp back, so the scheduler runs it again on
// the next start, not an interval later. *intent is the deposit intent it committed, if any.
func run(ctx context.Context, cfg *config.Config, rc recoveryclient.RunConfig, st store.Store, client recoveryclient.Depositor, intent *string) (recoveryclient.Result, error) {
	settings := Settings(context.WithoutCancel(ctx), st.Settings())
	// A replica that did not handle the pairing writes recovery.pub first. Its failure leaves
	// the file as it was, which the lib's own pin check below reports and audits.
	syncErr := SyncRecoveryKey(ctx, cfg, st)
	if syncErr != nil {
		log.Printf("[BACKUP] recovery.pub not synchronized with the pin: %s", recoveryclient.AuditSafe(syncErr.Error()))
	}
	prev, prevErr := settings.Get(lastAttemptKey)
	res, err := recoveryclient.Run(ctx, rc, settings, func() (recoveryclient.Payload, error) {
		payload, err := Collect(ctx, cfg, st, rc.AppVersion)
		if err == nil && recoveryclient.HasPairing(settings) {
			*intent, err = st.Intents().Begin(context.WithoutCancel(ctx), "deposit", rc.AppName)
		}
		return payload, err
	}, client)
	// A missing local file must not hide a failed shared-key read as "not paired".
	// Keep the attempt stamp so the actual failure is reported once per interval.
	if (errors.Is(err, recoveryclient.ErrNotPaired) || errors.Is(err, recoveryclient.ErrKeyPinMissing)) && syncErr != nil {
		err = syncErr
	}
	// ErrInProgress stamped nothing: the stamp belongs to the run that holds the lock.
	if err == nil || ctx.Err() == nil || res.Receipt != nil || errors.Is(err, recoveryclient.ErrInProgress) {
		return res, err
	}
	switch {
	case errors.Is(prevErr, recoveryclient.ErrNotFound):
		_ = settings.Delete(lastAttemptKey)
	case prevErr == nil:
		_ = settings.Set(lastAttemptKey, prev)
	}
	return res, fmt.Errorf("%w: %w", ErrInterrupted, err)
}

// RunOwned coordinates manual HTTP/CLI backups with the elected scheduler across hosts.
func RunOwned(ctx context.Context, cfg *config.Config, rc recoveryclient.RunConfig, st store.Store, client recoveryclient.Depositor, record Recorder) (recoveryclient.Result, error) {
	var result recoveryclient.Result
	won, err := st.Coordination().WithLock(ctx, "backup-run", func(owned context.Context) error {
		var err error
		result, err = Run(owned, cfg, rc, st, client, record)
		return err
	})
	if err == nil && !won {
		err = recoveryclient.ErrInProgress
	}
	return result, err
}
