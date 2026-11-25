package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/auditchain"
	"github.com/Busnes-app/ky-primitives/logging"
)

// The chained fields, in hash order (spec §9.3): action, user_id, resource, details,
// ip_address, created_at.
var (
	auditResource  = logging.DeclareString("resource")
	auditDetails   = logging.DeclareString("details")
	auditIP        = logging.DeclareString("ip_address")
	auditCreatedAt = logging.DeclareTime("created_at")
)

// auditFields renders r as the chain digests it. Values pass through logging.AuditFields,
// which sanitizes and bounds them; the stored columns are those rendered values, so what is
// stored is exactly what was hashed.
func auditFields(r *AuditRecord) []string {
	return logging.AuditFields(logging.Action(r.Action), logging.UserID(r.UserID), auditResource(r.Resource),
		auditDetails(r.Details), auditIP(r.IPAddress), auditCreatedAt(r.CreatedAt))
}

// normalizeAudit makes r's values the rendered ones and its time UTC with microsecond
// precision, the precision both databases keep.
func normalizeAudit(r *AuditRecord) {
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now()
	}
	r.CreatedAt = r.CreatedAt.UTC().Truncate(time.Microsecond)
	f := auditFields(r)
	value := func(i int) string { _, v, _ := strings.Cut(f[i], "="); return v }
	r.Action, r.UserID, r.Resource, r.Details, r.IPAddress = value(0), value(1), value(2), value(3), value(4)
}

// appendAudit is the one audit writer: it serializes on the chain (PostgreSQL advisory
// transaction lock; SQLite's _txlock=immediate already holds the write lock), reads the head,
// resumes the chain from the head record (or starts it when the head is absent and the log
// empty), and inserts the record and the new head in tx.
func (s *SQLStore) appendAudit(ctx context.Context, tx *sql.Tx, r *AuditRecord) error {
	chain, err := s.chainFor(ctx, tx)
	if err != nil {
		return err
	}
	normalizeAudit(r)
	_, err = chain.Append(ctx, func(rec auditchain.Record, a auditchain.Anchor) error {
		if _, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at, seq, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			r.UserID, r.Action, r.Resource, r.Details, r.IPAddress, r.CreatedAt, int64(rec.Seq), rec.Prev, rec.Hash); err != nil {
			return err
		}
		return s.putHead(ctx, tx, a)
	}, auditFields(r)...)
	return err
}

func (s *SQLStore) putHead(ctx context.Context, tx *sql.Tx, a auditchain.Anchor) error {
	_, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO audit_chain_head (id, seq, head_hash) VALUES (1, ?, ?) ON CONFLICT (id) DO UPDATE SET seq = excluded.seq, head_hash = excluded.head_hash`), int64(a.Count), a.Hash)
	return err
}

// chainFor serializes on the chain in tx and returns it resumed from the head record, or new
// when the head is absent and no record is chained yet.
func (s *SQLStore) chainFor(ctx context.Context, tx *sql.Tx) (*auditchain.Chain, error) {
	if len(s.auditKey) < 32 {
		return nil, errors.New("store: no audit chain key configured (config.DatabaseConfig.AuditKey); refusing an unchained audit write")
	}
	if s.driver == "postgres" {
		if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(4, hashtext('kyguard:auditchain'))`); err != nil {
			return nil, err
		}
	}
	head := `SELECT seq, head_hash FROM audit_chain_head WHERE id = 1`
	if s.driver == "postgres" {
		head += ` FOR UPDATE`
	}
	var seq int64
	var hash string
	var chain *auditchain.Chain
	switch err := tx.QueryRowContext(ctx, head).Scan(&seq, &hash); {
	case errors.Is(err, sql.ErrNoRows):
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_records WHERE seq IS NOT NULL`).Scan(&n); err != nil {
			return nil, err
		}
		if n != 0 {
			return nil, fmt.Errorf("%w: %d records but no head", auditchain.ErrBrokenChain, n)
		}
		if chain, err = auditchain.New(s.auditKey); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		last, err := s.auditRecordAt(ctx, tx, seq)
		if err != nil {
			return nil, err
		}
		if chain, err = auditchain.Resume(s.auditKey, last, auditchain.Anchor{Count: uint64(seq), Hash: hash}); err != nil {
			return nil, err
		}
	}
	return chain, nil
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
}

const auditChainColumns = `user_id, action, resource, details, ip_address, created_at, seq, prev_hash, hash`

func scanChained(row interface{ Scan(...any) error }) (auditchain.Record, error) {
	var r AuditRecord
	var seq int64
	var rec auditchain.Record
	if err := row.Scan(&r.UserID, &r.Action, &r.Resource, &r.Details, &r.IPAddress, &r.CreatedAt, &seq, &rec.Prev, &rec.Hash); err != nil {
		return rec, err
	}
	r.CreatedAt = r.CreatedAt.UTC()
	// The HMAC covers the canonical rendering; a stored value that renders the same but differs
	// (one a writer without the key changed) would otherwise verify and be shown as written.
	canonical := r
	normalizeAudit(&canonical)
	if canonical != r {
		return rec, fmt.Errorf("%w: record %d is not stored in its canonical form", auditchain.ErrBrokenChain, seq)
	}
	rec.Seq, rec.Fields = uint64(seq), auditFields(&r)
	return rec, nil
}

func (s *SQLStore) auditRecordAt(ctx context.Context, q queryer, seq int64) (auditchain.Record, error) {
	rec, err := scanChained(q.QueryRowContext(ctx, s.rebind(`SELECT `+auditChainColumns+` FROM audit_records WHERE seq = ?`), seq))
	if errors.Is(err, sql.ErrNoRows) {
		return rec, fmt.Errorf("%w: the head names record %d, which is missing", auditchain.ErrBrokenChain, seq)
	}
	return rec, err
}

// VerifyAuditChain checks every record against the chain key and the stored head. An empty
// log verifies against the genesis anchor (count 0, 64 zeros).
func (s *SQLStore) VerifyAuditChain(ctx context.Context) error {
	// One snapshot for the head and the records: under read committed an append between the two
	// reads would look like a broken chain.
	opts := &sql.TxOptions{}
	if s.driver == "postgres" {
		opts = &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true}
	}
	tx, err := s.db.BeginTx(ctx, opts)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var unchained int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_records WHERE seq IS NULL`).Scan(&unchained); err != nil {
		return err
	}
	if unchained > 0 {
		return fmt.Errorf("%w: %d records were never chained", auditchain.ErrBrokenChain, unchained)
	}
	anchor := auditchain.Anchor{Hash: strings.Repeat("0", 64)}
	var seq int64
	switch err := tx.QueryRowContext(ctx, `SELECT seq, head_hash FROM audit_chain_head WHERE id = 1`).Scan(&seq, &anchor.Hash); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	default:
		anchor.Count = uint64(seq)
	}
	rows, err := tx.QueryContext(ctx, `SELECT `+auditChainColumns+` FROM audit_records ORDER BY seq`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var recs []auditchain.Record
	for rows.Next() {
		rec, err := scanChained(rows)
		if err != nil {
			return err
		}
		recs = append(recs, rec)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	return auditchain.Verify(s.auditKey, recs, anchor)
}

// adoptLegacyAudit chains the records written before migration 15 (seq IS NULL), oldest
// first, in their canonical form, after any chained ones. Open runs it, so the first append
// finds one whole chain. A store without the chain key (a drill copy) leaves them.
func (s *SQLStore) adoptLegacyAudit(ctx context.Context) error {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_records WHERE seq IS NULL`).Scan(&n); err != nil || n == 0 || len(s.auditKey) < 32 {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	chain, err := s.chainFor(ctx, tx)
	if err != nil {
		return err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, user_id, action, resource, details, ip_address, created_at FROM audit_records WHERE seq IS NULL ORDER BY id`)
	if err != nil {
		return err
	}
	type legacy struct {
		id int64
		r  AuditRecord
	}
	var found []legacy
	for rows.Next() {
		var l legacy
		if err := rows.Scan(&l.id, &l.r.UserID, &l.r.Action, &l.r.Resource, &l.r.Details, &l.r.IPAddress, &l.r.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		found = append(found, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, l := range found {
		r := l.r
		normalizeAudit(&r)
		if _, err := chain.Append(ctx, func(rec auditchain.Record, a auditchain.Anchor) error {
			if _, err := tx.ExecContext(ctx, s.rebind(`UPDATE audit_records SET user_id = ?, action = ?, resource = ?, details = ?, ip_address = ?, created_at = ?, seq = ?, prev_hash = ?, hash = ? WHERE id = ?`),
				r.UserID, r.Action, r.Resource, r.Details, r.IPAddress, r.CreatedAt, int64(rec.Seq), rec.Prev, rec.Hash, l.id); err != nil {
				return err
			}
			return s.putHead(ctx, tx, a)
		}, auditFields(&r)...); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	log.Printf("[STORE] chained %d audit records written before the audit chain", len(found))
	return nil
}

type auditKey struct{}

// WithAudit asks the next user write made with ctx (CreateUser, the profile and role
// updates, LinkSSOIdentity) to append r in its own transaction, so the change and its record
// commit or fail together (spec §9.3).
func WithAudit(ctx context.Context, r *AuditRecord) context.Context {
	return context.WithValue(ctx, auditKey{}, r)
}

// appendCtxAudit appends the record WithAudit attached to ctx, if any.
func (s *SQLStore) appendCtxAudit(ctx context.Context, tx *sql.Tx) error {
	if r, ok := ctx.Value(auditKey{}).(*AuditRecord); ok && r != nil {
		return s.appendAudit(ctx, tx, r)
	}
	return nil
}
