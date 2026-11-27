package store

import (
	"context"
	"database/sql"
	"errors"
)

type BrowserKey struct {
	Enrollment string
	Sealed     string
}

func (g guardStore) BrowserKey(ctx context.Context, u *User) (*BrowserKey, error) {
	var k BrowserKey
	err := g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT enrollment, sealed FROM browser_keys
		WHERE user_id = ? AND issuer = ? AND subject = ?`), u.ID, u.SSOIssuer, u.SSOSubject).
		Scan(&k.Enrollment, &k.Sealed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &k, err
}

// PutBrowserKey saves the sealed key and draft together. A retry of the same upload
// is harmless, while a racing tab cannot replace the key the first tab enrolled.
func (g guardStore) PutBrowserKey(ctx context.Context, u *User, k BrowserKey, audit *AuditRecord) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO browser_keys (user_id, issuer, subject, enrollment, sealed)
			SELECT id, sso_issuer, sso_subject, ?, ? FROM users
			WHERE id = ? AND sso_issuer = ? AND sso_subject = ? AND status = 'active'
			ON CONFLICT (user_id) DO NOTHING`), k.Enrollment, k.Sealed, u.ID, u.SSOIssuer, u.SSOSubject)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 1 {
			return g.s.auditTx(ctx, tx, audit)
		}
		var current BrowserKey
		err = tx.QueryRowContext(ctx, g.s.rebind(`SELECT enrollment, sealed FROM browser_keys
			WHERE user_id = ? AND issuer = ? AND subject = ?`), u.ID, u.SSOIssuer, u.SSOSubject).
			Scan(&current.Enrollment, &current.Sealed)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && current != k) {
			return ErrConflict
		}
		return err
	})
}
