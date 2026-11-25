package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/crypto"
)

// intentStore implements IntentStore (spec §9.3).
type intentStore struct{ s *SQLStore }

func (s *SQLStore) Intents() IntentStore { return &intentStore{s: s} }

// notedOutcome is what Settle writes on the intent before its transaction: the state it ends
// in and its completion record.
type notedOutcome struct {
	State  string       `json:"state"`
	Record *AuditRecord `json:"record"`
}

func (i *intentStore) Begin(ctx context.Context, kind, subject string) (string, error) {
	id := "op_" + crypto.RandomHex(16)
	now := time.Now().UTC()
	_, err := i.s.db.ExecContext(ctx, i.s.rebind(`INSERT INTO operation_intents (operation_id, kind, subject, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`),
		id, kind, subject, IntentPending, now, now)
	return id, err
}

func (i *intentStore) Settle(ctx context.Context, operationID, state string, r *AuditRecord) error {
	if state == IntentPending || r == nil {
		return errors.New("store: an intent settles to a final state with a record")
	}
	noted, err := json.Marshal(notedOutcome{State: state, Record: r})
	if err != nil {
		return err
	}
	// Noted in its own commit, so an append that fails below is not lost: Reconcile replays it.
	if _, err := i.s.db.ExecContext(ctx, i.s.rebind(`UPDATE operation_intents SET outcome = ? WHERE operation_id = ? AND state = ?`),
		string(noted), operationID, IntentPending); err != nil {
		return err
	}
	return i.settle(ctx, operationID, state, r)
}

// settle moves a pending intent (or one reconciled as unknown meanwhile, which the real
// outcome corrects) to state and appends r, in one transaction. A completed deposit
// supersedes the deposits whose outcome was never learned.
func (i *intentStore) settle(ctx context.Context, operationID, state string, r *AuditRecord) error {
	tx, err := i.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	var kind string
	if err := tx.QueryRowContext(ctx, i.s.rebind(`SELECT kind FROM operation_intents WHERE operation_id = ? AND state IN (?, ?)`),
		operationID, IntentPending, IntentUnknown).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, i.s.rebind(`UPDATE operation_intents SET state = ?, updated_at = ? WHERE operation_id = ?`), state, now, operationID); err != nil {
		return err
	}
	if kind == "deposit" && state == IntentComplete {
		if _, err := tx.ExecContext(ctx, i.s.rebind(`UPDATE operation_intents SET state = ?, updated_at = ? WHERE kind = 'deposit' AND state = ? AND operation_id <> ?`),
			IntentSuperseded, now, IntentUnknown, operationID); err != nil {
			return err
		}
	}
	if err := i.s.appendAudit(ctx, tx, r); err != nil {
		return err
	}
	return tx.Commit()
}

func (i *intentStore) Reconcile(ctx context.Context, kind string, olderThan time.Duration) (int, error) {
	rows, err := i.s.db.QueryContext(ctx, i.s.rebind(`SELECT operation_id, subject, outcome FROM operation_intents WHERE kind = ? AND state = ? AND created_at <= ? ORDER BY created_at`),
		kind, IntentPending, time.Now().UTC().Add(-olderThan))
	if err != nil {
		return 0, err
	}
	type stale struct{ id, subject, outcome string }
	var found []stale
	for rows.Next() {
		var st stale
		if err := rows.Scan(&st.id, &st.subject, &st.outcome); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, st)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for n, st := range found {
		var noted notedOutcome
		if st.outcome == "" || json.Unmarshal([]byte(st.outcome), &noted) != nil || noted.Record == nil {
			noted = notedOutcome{State: IntentUnknown, Record: &AuditRecord{UserID: "system", Action: "operation.outcome_unknown",
				Resource: kind + ":" + st.subject, Details: "severity=critical operation_id=" + st.id}}
		}
		if err := i.settle(ctx, st.id, noted.State, noted.Record); errors.Is(err, ErrNotFound) {
			continue // settled meanwhile by its own process
		} else if err != nil {
			return n, err
		}
	}
	return len(found), nil
}

func (i *intentStore) Get(ctx context.Context, operationID string) (*Intent, error) {
	var in Intent
	err := i.s.db.QueryRowContext(ctx, i.s.rebind(`SELECT operation_id, kind, subject, state, created_at, updated_at FROM operation_intents WHERE operation_id = ?`), operationID).
		Scan(&in.OperationID, &in.Kind, &in.Subject, &in.State, &in.CreatedAt, &in.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &in, err
}
