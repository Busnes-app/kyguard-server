package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// DraftStore holds policy drafts awaiting Custodian signatures (spec §9.2, §10). One draft
// per account; the object is canonical JSON with whatever signatures were collected.
type DraftStore interface {
	ListDrafts(ctx context.Context) ([]*PolicyDraft, error)
	GetDraft(ctx context.Context, id string) (*PolicyDraft, error)
	// PutDraft replaces the account's draft (signatures and all) or creates it.
	PutDraft(ctx context.Context, d *PolicyDraft, audit *AuditRecord) error
	// SetDraftObject replaces the stored object only while it is still prev, the object the
	// caller checked; ErrConflict when the draft is gone or changed meanwhile. The digest
	// leaves signatures out, so it cannot detect a concurrent signature change.
	SetDraftObject(ctx context.Context, id string, prev, object []byte, audit *AuditRecord) error
	DeleteDraft(ctx context.Context, id string, audit *AuditRecord) error
	// TakeDraft deletes the draft only while its object is still prev; ErrConflict otherwise.
	TakeDraft(ctx context.Context, id string, prev []byte, audit *AuditRecord) error
}

// PolicyDraft is an unsigned or partly signed PolicyManifest.
type PolicyDraft struct {
	ID        string    `json:"id"`
	AccountID string    `json:"account_id"`
	Epoch     uint64    `json:"epoch"`
	Digest    string    `json:"digest"`
	Object    []byte    `json:"-"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type draftStore struct{ s *SQLStore }

func (s *SQLStore) Drafts() DraftStore { return draftStore{s} }

const draftCols = `id, account_id, epoch, digest, object, created_by, created_at, updated_at`

func scanDraft(row interface{ Scan(...any) error }) (*PolicyDraft, error) {
	var d PolicyDraft
	var epoch int64
	var obj string
	err := row.Scan(&d.ID, &d.AccountID, &epoch, &d.Digest, &obj, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	d.Epoch, d.Object = uint64(epoch), []byte(obj)
	return &d, err
}

func (v draftStore) ListDrafts(ctx context.Context) ([]*PolicyDraft, error) {
	rows, err := v.s.db.QueryContext(ctx, `SELECT `+draftCols+` FROM policy_drafts ORDER BY updated_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*PolicyDraft{}
	for rows.Next() {
		d, err := scanDraft(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (v draftStore) GetDraft(ctx context.Context, id string) (*PolicyDraft, error) {
	return scanDraft(v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT `+draftCols+` FROM policy_drafts WHERE id = ?`), id))
}

func (v draftStore) PutDraft(ctx context.Context, d *PolicyDraft, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		d.CreatedAt, d.UpdatedAt = now, now
		if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM policy_drafts WHERE account_id = ?`), d.AccountID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO policy_drafts (`+draftCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			d.ID, d.AccountID, int64(d.Epoch), d.Digest, string(d.Object), d.CreatedBy, now, now); err != nil {
			return uniqueErr(err)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v draftStore) SetDraftObject(ctx context.Context, id string, prev, object []byte, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE policy_drafts SET object = ?, updated_at = ? WHERE id = ? AND object = ?`), string(object), time.Now().UTC(), id, string(prev))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return errors.Join(err, ErrConflict)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v draftStore) DeleteDraft(ctx context.Context, id string, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM policy_drafts WHERE id = ?`), id)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return errors.Join(err, ErrNotFound)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v draftStore) TakeDraft(ctx context.Context, id string, prev []byte, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM policy_drafts WHERE id = ? AND object = ?`), id, string(prev))
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return errors.Join(err, ErrConflict)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}
