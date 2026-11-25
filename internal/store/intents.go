package store

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/crypto"
)

// intentStore implements IntentStore (spec §9.3).
type intentStore struct{ s *SQLStore }

func (s *SQLStore) Intents() IntentStore { return &intentStore{s: s} }

// notedOutcome is what Settle writes on the intent before its transaction: the state it ends
// in and its completion record, authenticated (MAC) so that reconciliation replays only what
// this server noted, never a row a database writer without the key edited.
type notedOutcome struct {
	State  string          `json:"state"`
	Record json.RawMessage `json:"record"`
	MAC    string          `json:"mac"`
}

// outcomeMAC binds a noted outcome to its intent: operation ID, kind, subject, final state
// and the exact record bytes, under a key derived from the audit chain key.
func (i *intentStore) outcomeMAC(id, kind, subject, state string, record []byte) (string, error) {
	if len(i.s.auditKey) < 32 {
		return "", errors.New("store: no audit chain key configured; refusing to note an outcome")
	}
	key, err := hkdf.Key(sha256.New, i.s.auditKey, nil, "kyguard:intent-outcome", 32)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, key)
	for _, f := range [][]byte{[]byte(id), []byte(kind), []byte(subject), []byte(state), record} {
		_ = binary.Write(m, binary.BigEndian, uint32(len(f)))
		m.Write(f)
	}
	return hex.EncodeToString(m.Sum(nil)), nil
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
	in, err := i.Get(ctx, operationID)
	if err != nil {
		return err
	}
	record, err := json.Marshal(r)
	if err != nil {
		return err
	}
	mac, err := i.outcomeMAC(in.OperationID, in.Kind, in.Subject, state, record)
	if err != nil {
		return err
	}
	noted, err := json.Marshal(notedOutcome{State: state, Record: record, MAC: mac})
	if err != nil {
		return err
	}
	// Noted in its own commit, so an append that fails below is not lost: Reconcile replays it.
	if _, err := i.s.db.ExecContext(ctx, i.s.rebind(`UPDATE operation_intents SET outcome = ? WHERE operation_id = ? AND state = ?`),
		string(noted), operationID, IntentPending); err != nil {
		return err
	}
	// The process that ran the effect may correct an intent reconciled as unknown meanwhile.
	return i.settle(ctx, operationID, state, r, IntentPending, IntentUnknown)
}

// settle moves the intent from one of the states in from to state and appends r, in one
// transaction. The move is one conditional UPDATE, so of two concurrent settlers only one
// appends a record; the other gets ErrNotFound. A completed deposit supersedes the deposits
// whose outcome was never learned.
func (i *intentStore) settle(ctx context.Context, operationID, state string, r *AuditRecord, from ...string) error {
	tx, err := i.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	args := []any{state, now, operationID}
	marks := make([]string, len(from))
	for n, f := range from {
		marks[n], args = "?", append(args, f)
	}
	var kind string
	if err := tx.QueryRowContext(ctx, i.s.rebind(`UPDATE operation_intents SET state = ?, updated_at = ? WHERE operation_id = ? AND state IN (`+strings.Join(marks, ", ")+`) RETURNING kind`),
		args...).Scan(&kind); errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	} else if err != nil {
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
		state, rec := i.replay(kind, st.id, st.subject, st.outcome)
		// Only from pending: of concurrent reconcilers one settles it, and an outcome its own
		// process already wrote is never replayed over.
		if err := i.settle(ctx, st.id, state, rec, IntentPending); errors.Is(err, ErrNotFound) {
			continue
		} else if err != nil {
			return n, err
		}
	}
	return len(found), nil
}

// replay is how reconciliation ends a pending intent: its noted outcome when this server's MAC
// authenticates it, else outcome_unknown. A note that fails authentication is never appended;
// its rejection is recorded instead.
func (i *intentStore) replay(kind, id, subject, outcome string) (string, *AuditRecord) {
	unknown := func(action, why string) (string, *AuditRecord) {
		return IntentUnknown, &AuditRecord{UserID: "system", Action: action, Resource: kind + ":" + subject, Details: "severity=critical operation_id=" + id + why}
	}
	if outcome == "" {
		return unknown("operation.outcome_unknown", "")
	}
	var noted notedOutcome
	var rec AuditRecord
	if json.Unmarshal([]byte(outcome), &noted) != nil || noted.State == IntentPending || json.Unmarshal(noted.Record, &rec) != nil {
		return unknown("operation.outcome_rejected", " reason=unreadable_note")
	}
	want, err := i.outcomeMAC(id, kind, subject, noted.State, noted.Record)
	if err != nil || !hmac.Equal([]byte(want), []byte(noted.MAC)) {
		return unknown("operation.outcome_rejected", " reason=note_not_authenticated")
	}
	return noted.State, &rec
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
