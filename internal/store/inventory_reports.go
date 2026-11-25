package store

import (
	"context"
	"time"
)

// ReportFacts are the per-account rows the classifier reads (spec §8.1).
type ReportFacts struct {
	LastRelease time.Time // newest release receipt; zero when none
	OpenLeases  int
}

// JobRun is a rotation run as the jobs screen shows it (§10).
type JobRun struct {
	OperationID   string    `json:"operation_id"`
	AccountID     string    `json:"account_id"`
	BrokerID      string    `json:"broker_id"`
	SecretVersion uint64    `json:"secret_version"`
	State         string    `json:"state"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

func (v inventoryStore) ReportFacts(ctx context.Context) (map[string]*ReportFacts, error) {
	out := map[string]*ReportFacts{}
	get := func(id string) *ReportFacts {
		if out[id] == nil {
			out[id] = &ReportFacts{}
		}
		return out[id]
	}
	// Rows, not MAX(): SQLite hands an aggregate timestamp back as text.
	rows, err := v.s.db.QueryContext(ctx, `SELECT e.account_id, r.created_at FROM envelope_receipts r
		JOIN secret_envelopes e ON e.envelope_id = r.envelope_id WHERE r.receipt_type = 'release'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var at time.Time
		if err := rows.Scan(&id, &at); err != nil {
			return nil, err
		}
		if f := get(id); at.After(f.LastRelease) {
			f.LastRelease = at
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	leases, err := v.s.db.QueryContext(ctx, `SELECT account_id FROM checkout_leases WHERE state <> 'closed'`)
	if err != nil {
		return nil, err
	}
	defer leases.Close()
	for leases.Next() {
		var id string
		if err := leases.Scan(&id); err != nil {
			return nil, err
		}
		get(id).OpenLeases++
	}
	return out, leases.Err()
}

func (v inventoryStore) RecentRuns(ctx context.Context, limit int) ([]*JobRun, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT operation_id, account_id, broker_id, secret_version, state, created_at, updated_at
		FROM rotation_runs ORDER BY updated_at DESC, operation_id LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*JobRun{}
	for rows.Next() {
		var j JobRun
		var ver int64
		if err := rows.Scan(&j.OperationID, &j.AccountID, &j.BrokerID, &ver, &j.State, &j.CreatedAt, &j.UpdatedAt); err != nil {
			return nil, err
		}
		j.SecretVersion = uint64(ver)
		out = append(out, &j)
	}
	return out, rows.Err()
}

// JobLease is a checkout lease as the jobs screen shows it.
type JobLease struct {
	RequestID   string    `json:"request_id"`
	AccountID   string    `json:"account_id"`
	BrokerID    string    `json:"broker_id"`
	State       string    `json:"state"`
	CloseReason string    `json:"close_reason"`
	OpenedAt    time.Time `json:"opened_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func (v inventoryStore) RecentLeases(ctx context.Context, limit int) ([]*JobLease, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT request_id, account_id, broker_id, state, close_reason, opened_at, expires_at
		FROM checkout_leases ORDER BY (state = 'closed'), opened_at DESC LIMIT ?`), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*JobLease{}
	for rows.Next() {
		var l JobLease
		if err := rows.Scan(&l.RequestID, &l.AccountID, &l.BrokerID, &l.State, &l.CloseReason, &l.OpenedAt, &l.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}
