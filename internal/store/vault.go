package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// ErrLocked means another operation holds the account's rotation lock.
var ErrLocked = errors.New("account rotation lock is held by another operation")

// LockAction is what Complete does with the lock op holds.
type LockAction int

// Lock actions.
const (
	LockKeep    LockAction = iota
	LockDelete             // delete op's lock; never another's
	LockRestore            // delete op's enrollment lock and reinstate the holder it displaced
)

// VaultStore holds accounts, envelopes, receipts and rotation state (spec §3.5, §4.3, §9.2).
// Signed objects are stored as their exact canonical bytes; callers verify them first.
type VaultStore interface {
	CreateAsset(ctx context.Context, a *Asset) error
	CreateAccount(ctx context.Context, a *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	PoolAccounts(ctx context.Context, poolID string) ([]*Account, error)
	// PutTargetDescriptor stores a descriptor by digest; storing it again is a no-op.
	PutTargetDescriptor(ctx context.Context, digest, accountID string, raw []byte) error
	TargetDescriptor(ctx context.Context, digest string) ([]byte, error)

	// Reserve takes the account's rotation lock for op and allocates one more than the
	// highest version ever allocated or reported (reported is the broker's high-water mark,
	// §3.7). A retry by the same op returns the same version; ErrLocked if another op holds it.
	Reserve(ctx context.Context, accountID, op string, reported uint64) (uint64, error)
	// PutEnvelope stores a sealed candidate under op's lock at the reserved version. Storing
	// the same bytes again is a no-op.
	PutEnvelope(ctx context.Context, op string, e *StoredEnvelope) error
	// RecordIntent stores a mutating intent in rotation_runs under op's lock (§4.3 rule 2).
	// The same record again is a no-op; a different one for op is ErrConflict.
	RecordIntent(ctx context.Context, r *RotationRun) error
	// EnvelopeByDigest returns a stored envelope's bytes.
	EnvelopeByDigest(ctx context.Context, digest string) ([]byte, error)
	// Chains returns every envelope of the account with its receipts in order.
	Chains(ctx context.Context, accountID string) ([]*StoredChain, error)
	// Complete appends receipts by compare-and-swap (a byte-identical re-append is a no-op),
	// marks the run of every envelope an abort receipt names aborted, sets
	// current_envelope_id when current is non-empty, moves op's run to runState when
	// non-empty, and applies lock to the lock held by op. One transaction (§4.3 rule 7, §4.5).
	Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, lock LockAction) error
	// ReserveEnrollment moves the account's lock to op as a reserved enrollment with a new
	// version, keeping the holder it displaces (a stuck rotation) to restore later. It is
	// allowed when no lock is held or the account is quarantined (§4.5 step 1); a retry by
	// op returns the same version.
	ReserveEnrollment(ctx context.Context, accountID, op string, reported uint64, now time.Time, ttl time.Duration) (uint64, error)
	// AcceptEnrollment moves op's reservation from reserved to accepted by compare-and-swap;
	// ErrConflict if it expired or is not op's. Accepting twice is a no-op.
	AcceptEnrollment(ctx context.Context, accountID, op string, now time.Time) error
	// ExpireEnrollments releases every reservation still reserved past its expiry and
	// restores the holder it displaced. An accepted reservation never expires.
	ExpireEnrollments(ctx context.Context, now time.Time) (int, error)
	// EnrollmentState is reserved or accepted while op holds the lock, then committed or
	// failed by its receipts, else expired.
	EnrollmentState(ctx context.Context, accountID, op string) (string, error)
	// MirrorLease upserts the broker's view of a checkout lease (§3.6 step 3). At most one
	// non-closed lease per account is a database constraint.
	MirrorLease(ctx context.Context, l *Lease) error
	GetLease(ctx context.Context, requestID string) (*Lease, error)
	// TxMailbox holds what the broker sent back for a transaction: a challenge, a delivery
	// wrap, a refusal. SetTxMailbox sets one field; an empty value leaves it.
	TxMailbox(ctx context.Context, requestID string) (*TxMail, error)
	SetTxMailbox(ctx context.Context, requestID string, m *TxMail) error
	// TxAccount is the account a stored transaction names.
	TxAccount(ctx context.Context, requestID string) (string, error)
	// PutTx stores a relayed transaction once.
	PutTx(ctx context.Context, requestID, accountID, actionType, digest string, raw []byte) error
	SetHealth(ctx context.Context, accountID, health, reason string) error
	// Lock returns the operation holding the account's lock, or "".
	Lock(ctx context.Context, accountID string) (op string, version uint64, err error)
	GetRun(ctx context.Context, accountID, op string) (*RotationRun, error)
}

// Asset is a host or directory that accounts live on.
type Asset struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// Account is a privileged account. Only the columns the broker stack needs are here; the
// inventory work adds the rest.
type Account struct {
	ID                   string
	AssetID              string
	Name                 string
	AccountKind          string
	PoolID               string
	Status               string
	CurrentEnvelopeID    string
	HighestSecretVersion uint64
	Health               string
	HealthReason         string
	CreatedAt            time.Time
}

// Lease is a checkout lease as the broker reports it.
type Lease struct {
	RequestID     string
	AccountID     string
	BrokerID      string
	SecretVersion uint64
	State         string
	CloseReason   string
	OpenedAt      time.Time
	ExpiresAt     time.Time
}

// TxMail is the Control Plane's relay mailbox for one transaction.
type TxMail struct {
	Challenge string // base64url
	Purpose   string
	Delivery  string // canonical JSON of the user wrap
	Result    string // a refusal code, or "ok"
}

// StoredEnvelope is a verified SecretEnvelope.
type StoredEnvelope struct {
	EnvelopeID    string
	AccountID     string
	SecretVersion uint64
	EnvelopeKind  string
	Digest        string
	Envelope      []byte
}

// StoredReceipt is a verified EnvelopeReceipt.
type StoredReceipt struct {
	EnvelopeID      string
	ReceiptSeq      uint64
	ReceiptType     string
	OperationID     string
	Digest          string
	PrevReceiptHash string
	Receipt         []byte
}

// StoredChain is an envelope and its receipts.
type StoredChain struct {
	Envelope *StoredEnvelope
	Receipts []*StoredReceipt
}

// RotationRun mirrors a broker's mutating intent.
type RotationRun struct {
	OperationID   string
	AccountID     string
	BrokerID      string
	SecretVersion uint64
	Intent        []byte // canonical JSON of the intent the broker journaled
	State         string
}

type vaultStore struct{ s *SQLStore }

func (s *SQLStore) Vault() VaultStore { return vaultStore{s} }

func (v vaultStore) CreateAsset(ctx context.Context, a *Asset) error {
	_, err := v.s.db.ExecContext(ctx, v.s.rebind(`INSERT INTO assets (id, name, created_at) VALUES (?, ?, ?)`), a.ID, a.Name, time.Now().UTC())
	return err
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func (v vaultStore) CreateAccount(ctx context.Context, a *Account) error {
	_, err := v.s.db.ExecContext(ctx, v.s.rebind(`INSERT INTO accounts (id, asset_id, name, account_kind, pool_id, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
		a.ID, a.AssetID, a.Name, a.AccountKind, nullable(a.PoolID), time.Now().UTC())
	return err
}

const accountCols = `id, asset_id, name, account_kind, COALESCE(pool_id, ''), status, COALESCE(current_envelope_id, ''), highest_secret_version, health, health_reason, created_at`

func scanAccount(row interface{ Scan(...any) error }) (*Account, error) {
	var a Account
	var hv int64
	err := row.Scan(&a.ID, &a.AssetID, &a.Name, &a.AccountKind, &a.PoolID, &a.Status, &a.CurrentEnvelopeID, &hv, &a.Health, &a.HealthReason, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.HighestSecretVersion = uint64(hv)
	return &a, err
}

func (v vaultStore) GetAccount(ctx context.Context, id string) (*Account, error) {
	return scanAccount(v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT `+accountCols+` FROM accounts WHERE id = ?`), id))
}

func (v vaultStore) PoolAccounts(ctx context.Context, poolID string) ([]*Account, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT `+accountCols+` FROM accounts WHERE pool_id = ? ORDER BY id`), poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Account
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (v vaultStore) PutTargetDescriptor(ctx context.Context, digest, accountID string, raw []byte) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COUNT(1) FROM target_descriptors WHERE digest = ?`), digest).Scan(&n); err != nil || n > 0 {
			return err
		}
		_, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO target_descriptors (digest, account_id, descriptor, created_at) VALUES (?, ?, ?, ?)`), digest, accountID, string(raw), time.Now().UTC())
		return err
	})
}

func (v vaultStore) TargetDescriptor(ctx context.Context, digest string) ([]byte, error) {
	var raw string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT descriptor FROM target_descriptors WHERE digest = ?`), digest).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return []byte(raw), err
}

// lockAccount serializes writers on one account row (PostgreSQL row lock; SQLite has one
// writer connection).
func (v vaultStore) lockAccount(ctx context.Context, tx *sql.Tx, accountID string) (uint64, error) {
	q := `SELECT highest_secret_version FROM accounts WHERE id = ?`
	if v.s.driver == "postgres" {
		q += ` FOR UPDATE`
	}
	var hv int64
	err := tx.QueryRowContext(ctx, v.s.rebind(q), accountID).Scan(&hv)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return uint64(hv), err
}

func (v vaultStore) heldBy(ctx context.Context, tx *sql.Tx, accountID string) (string, uint64, error) {
	var op string
	var ver int64
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT operation_id, secret_version FROM rotation_locks WHERE account_id = ?`), accountID).Scan(&op, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return op, uint64(ver), err
}

func (v vaultStore) Reserve(ctx context.Context, accountID, op string, reported uint64) (uint64, error) {
	var version uint64
	err := v.s.inTx(ctx, func(tx *sql.Tx) error {
		highest, err := v.lockAccount(ctx, tx, accountID)
		if err != nil {
			return err
		}
		holder, held, err := v.heldBy(ctx, tx, accountID)
		if err != nil {
			return err
		}
		if holder == op {
			version = held
			return nil
		}
		if holder != "" {
			return ErrLocked
		}
		version = max(highest, reported) + 1
		if version > 1<<63-1 {
			return errors.New("secret_version exhausted")
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET highest_secret_version = ? WHERE id = ?`), int64(version), accountID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO rotation_locks (account_id, operation_id, secret_version, created_at) VALUES (?, ?, ?, ?)`),
			accountID, op, int64(version), time.Now().UTC())
		return err
	})
	return version, err
}

func (v vaultStore) requireLock(ctx context.Context, tx *sql.Tx, accountID, op string, version uint64) error {
	if _, err := v.lockAccount(ctx, tx, accountID); err != nil {
		return err
	}
	holder, held, err := v.heldBy(ctx, tx, accountID)
	if err != nil {
		return err
	}
	if holder != op || held != version {
		return ErrLocked
	}
	return nil
}

func (v vaultStore) PutEnvelope(ctx context.Context, op string, e *StoredEnvelope) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		var have string
		err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT envelope FROM secret_envelopes WHERE envelope_id = ?`), e.EnvelopeID).Scan(&have)
		if err == nil {
			if have == string(e.Envelope) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := v.requireLock(ctx, tx, e.AccountID, op, e.SecretVersion); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO secret_envelopes (envelope_id, account_id, secret_version, envelope_kind, digest, envelope, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			e.EnvelopeID, e.AccountID, int64(e.SecretVersion), e.EnvelopeKind, e.Digest, string(e.Envelope), time.Now().UTC())
		return err
	})
}

func (v vaultStore) RecordIntent(ctx context.Context, r *RotationRun) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		var have string
		err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT intent FROM rotation_runs WHERE account_id = ? AND operation_id = ?`), r.AccountID, r.OperationID).Scan(&have)
		if err == nil {
			if have == string(r.Intent) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if err := v.requireLock(ctx, tx, r.AccountID, r.OperationID, r.SecretVersion); err != nil {
			return err
		}
		now := time.Now().UTC()
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO rotation_runs (operation_id, account_id, broker_id, secret_version, intent, state, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'mutating', ?, ?)`),
			r.OperationID, r.AccountID, r.BrokerID, int64(r.SecretVersion), string(r.Intent), now, now)
		return err
	})
}

func (v vaultStore) Chains(ctx context.Context, accountID string) ([]*StoredChain, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT envelope_id, account_id, secret_version, envelope_kind, digest, envelope FROM secret_envelopes WHERE account_id = ? ORDER BY secret_version`), accountID)
	if err != nil {
		return nil, err
	}
	var out []*StoredChain
	byID := map[string]*StoredChain{}
	for rows.Next() {
		var e StoredEnvelope
		var ver int64
		var raw string
		if err := rows.Scan(&e.EnvelopeID, &e.AccountID, &ver, &e.EnvelopeKind, &e.Digest, &raw); err != nil {
			rows.Close()
			return nil, err
		}
		e.SecretVersion, e.Envelope = uint64(ver), []byte(raw)
		c := &StoredChain{Envelope: &e}
		out = append(out, c)
		byID[e.EnvelopeID] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = v.s.db.QueryContext(ctx, v.s.rebind(`SELECT r.envelope_id, r.receipt_seq, r.receipt_type, r.operation_id, r.digest, r.prev_receipt_hash, r.receipt
FROM envelope_receipts r JOIN secret_envelopes e ON e.envelope_id = r.envelope_id WHERE e.account_id = ? ORDER BY r.envelope_id, r.receipt_seq`), accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r StoredReceipt
		var seq int64
		var raw string
		if err := rows.Scan(&r.EnvelopeID, &seq, &r.ReceiptType, &r.OperationID, &r.Digest, &r.PrevReceiptHash, &raw); err != nil {
			return nil, err
		}
		r.ReceiptSeq, r.Receipt = uint64(seq), []byte(raw)
		// An envelope committed between the two reads is left for the next call.
		if c := byID[r.EnvelopeID]; c != nil {
			c.Receipts = append(c.Receipts, &r)
		}
	}
	return out, rows.Err()
}

// appendReceipt is the §3.5 compare-and-swap: seq must be head+1 and prev the head hash.
func (v vaultStore) appendReceipt(ctx context.Context, tx *sql.Tx, r *StoredReceipt) error {
	var have string
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT receipt FROM envelope_receipts WHERE envelope_id = ? AND receipt_seq = ?`), r.EnvelopeID, int64(r.ReceiptSeq)).Scan(&have)
	if err == nil {
		if have == string(r.Receipt) {
			return nil // a retry after restart
		}
		return ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	var headSeq int64
	var headHash sql.NullString
	if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COALESCE(MAX(receipt_seq), 0), (SELECT digest FROM envelope_receipts WHERE envelope_id = ? ORDER BY receipt_seq DESC LIMIT 1) FROM envelope_receipts WHERE envelope_id = ?`),
		r.EnvelopeID, r.EnvelopeID).Scan(&headSeq, &headHash); err != nil {
		return err
	}
	prev := zeroHash
	if headHash.Valid {
		prev = headHash.String
	}
	if r.ReceiptSeq != uint64(headSeq)+1 || r.PrevReceiptHash != prev {
		return ErrConflict
	}
	_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO envelope_receipts (envelope_id, receipt_seq, receipt_type, operation_id, digest, prev_receipt_hash, receipt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		r.EnvelopeID, int64(r.ReceiptSeq), r.ReceiptType, r.OperationID, r.Digest, r.PrevReceiptHash, string(r.Receipt), time.Now().UTC())
	return err
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (v vaultStore) Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, lock LockAction) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := v.lockAccount(ctx, tx, accountID); err != nil {
			return err
		}
		for _, r := range rs {
			var owner string
			if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT account_id FROM secret_envelopes WHERE envelope_id = ?`), r.EnvelopeID).Scan(&owner); err != nil || owner != accountID {
				if err == nil || errors.Is(err, sql.ErrNoRows) {
					err = ErrNotFound
				}
				return err
			}
			if err := v.appendReceipt(ctx, tx, r); err != nil {
				return err
			}
			if r.ReceiptType == "abort" {
				if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_runs SET state = 'aborted', updated_at = ?
WHERE account_id = ? AND state <> 'release_authorized' AND secret_version = (SELECT secret_version FROM secret_envelopes WHERE envelope_id = ?)`),
					time.Now().UTC(), accountID, r.EnvelopeID); err != nil {
					return err
				}
			}
		}
		if current != "" {
			if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET current_envelope_id = ? WHERE id = ?`), current, accountID); err != nil {
				return err
			}
		}
		if runState != "" {
			if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_runs SET state = ?, updated_at = ? WHERE operation_id = ? AND account_id = ?`), runState, time.Now().UTC(), op, accountID); err != nil {
				return err
			}
		}
		switch lock {
		case LockDelete:
			// A delete by operation_id: it never removes another operation's lock (§4.3 rule 7).
			if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM rotation_locks WHERE account_id = ? AND operation_id = ?`), accountID, op); err != nil {
				return err
			}
		case LockRestore:
			return v.restore(ctx, tx, accountID, op)
		}
		return nil
	})
}

// restore deletes op's enrollment lock and reinstates the holder it displaced, if any.
func (v vaultStore) restore(ctx context.Context, tx *sql.Tx, accountID, op string) error {
	var prev sql.NullString
	var prevVer sql.NullInt64
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT previous_operation_id, previous_secret_version FROM rotation_locks WHERE account_id = ? AND operation_id = ? AND kind = 'enrollment'`),
		accountID, op).Scan(&prev, &prevVer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // already released
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM rotation_locks WHERE account_id = ? AND operation_id = ?`), accountID, op); err != nil {
		return err
	}
	if !prev.Valid {
		return nil
	}
	_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO rotation_locks (account_id, operation_id, secret_version, created_at) VALUES (?, ?, ?, ?)`),
		accountID, prev.String, prevVer.Int64, time.Now().UTC())
	return err
}

func (v vaultStore) ReserveEnrollment(ctx context.Context, accountID, op string, reported uint64, now time.Time, ttl time.Duration) (uint64, error) {
	// Expiry commits on its own: a refusal below must not roll it back.
	if err := v.s.inTx(ctx, func(tx *sql.Tx) error { return v.expire(ctx, tx, accountID, now) }); err != nil {
		return 0, err
	}
	var version uint64
	err := v.s.inTx(ctx, func(tx *sql.Tx) error {
		highest, err := v.lockAccount(ctx, tx, accountID)
		if err != nil {
			return err
		}
		var health string
		if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT health FROM accounts WHERE id = ?`), accountID).Scan(&health); err != nil {
			return err
		}
		holder, held, err := v.heldBy(ctx, tx, accountID)
		if err != nil {
			return err
		}
		if holder == op {
			version = held
			return nil
		}
		quarantined := health == "quarantined" || health == "auth_failed"
		var kind string
		if holder != "" {
			if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT kind FROM rotation_locks WHERE account_id = ?`), accountID).Scan(&kind); err != nil {
				return err
			}
		}
		if holder != "" && (!quarantined || kind == "enrollment") {
			return ErrLocked // an open rotation on a healthy account, or another enrollment
		}
		version = max(highest, reported) + 1
		if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET highest_secret_version = ? WHERE id = ?`), int64(version), accountID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM rotation_locks WHERE account_id = ?`), accountID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO rotation_locks (account_id, operation_id, secret_version, created_at, kind, state, previous_operation_id, previous_secret_version, expires_at)
VALUES (?, ?, ?, ?, 'enrollment', 'reserved', ?, ?, ?)`), accountID, op, int64(version), now, nullable(holder), nullVersion(holder, held), now.Add(ttl))
		return err
	})
	return version, err
}

func nullVersion(holder string, v uint64) any {
	if holder == "" {
		return nil
	}
	return int64(v)
}

// expire restores the displaced holder of an account's expired reservation.
func (v vaultStore) expire(ctx context.Context, tx *sql.Tx, accountID string, now time.Time) error {
	var op string
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT operation_id FROM rotation_locks WHERE account_id = ? AND kind = 'enrollment' AND state = 'reserved' AND expires_at <= ?`), accountID, now).Scan(&op)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return v.restore(ctx, tx, accountID, op)
}

func (v vaultStore) AcceptEnrollment(ctx context.Context, accountID, op string, now time.Time) error {
	// Expiry commits on its own: the refused CAS below must not roll it back.
	if err := v.s.inTx(ctx, func(tx *sql.Tx) error { return v.expire(ctx, tx, accountID, now) }); err != nil {
		return err
	}
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_locks SET state = 'accepted' WHERE account_id = ? AND operation_id = ? AND kind = 'enrollment' AND state IN ('reserved', 'accepted')`), accountID, op)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			if err == nil {
				err = ErrConflict
			}
			return err
		}
		return nil
	})
}

func (v vaultStore) ExpireEnrollments(ctx context.Context, now time.Time) (int, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT account_id FROM rotation_locks WHERE kind = 'enrollment' AND state = 'reserved' AND expires_at <= ?`), now)
	if err != nil {
		return 0, err
	}
	var accts []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			rows.Close()
			return 0, err
		}
		accts = append(accts, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, a := range accts {
		if err := v.s.inTx(ctx, func(tx *sql.Tx) error { return v.expire(ctx, tx, a, now) }); err != nil {
			return 0, err
		}
	}
	return len(accts), nil
}

func (v vaultStore) PutTx(ctx context.Context, requestID, accountID, actionType, digest string, raw []byte) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		var have string
		err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT tx FROM access_transactions WHERE request_id = ?`), requestID).Scan(&have)
		if err == nil {
			if have == string(raw) {
				return nil
			}
			return ErrConflict
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO access_transactions (request_id, account_id, action_type, digest, tx, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
			requestID, accountID, actionType, digest, string(raw), time.Now().UTC())
		return err
	})
}

func (v vaultStore) SetHealth(ctx context.Context, accountID, health, reason string) error {
	_, err := v.s.db.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET health = ?, health_reason = ? WHERE id = ?`), health, reason, accountID)
	return err
}

func (v vaultStore) Lock(ctx context.Context, accountID string) (string, uint64, error) {
	var op string
	var ver int64
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT operation_id, secret_version FROM rotation_locks WHERE account_id = ?`), accountID).Scan(&op, &ver)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, nil
	}
	return op, uint64(ver), err
}

func (v vaultStore) GetRun(ctx context.Context, accountID, op string) (*RotationRun, error) {
	var r RotationRun
	var ver int64
	var intent string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT operation_id, account_id, broker_id, secret_version, intent, state FROM rotation_runs WHERE account_id = ? AND operation_id = ?`), accountID, op).
		Scan(&r.OperationID, &r.AccountID, &r.BrokerID, &ver, &intent, &r.State)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	r.SecretVersion, r.Intent = uint64(ver), []byte(intent)
	return &r, err
}

func (v vaultStore) EnvelopeByDigest(ctx context.Context, digest string) ([]byte, error) {
	var raw string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT envelope FROM secret_envelopes WHERE digest = ?`), digest).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return []byte(raw), err
}

func (v vaultStore) EnrollmentState(ctx context.Context, accountID, op string) (string, error) {
	var state string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT state FROM rotation_locks WHERE account_id = ? AND operation_id = ? AND kind = 'enrollment'`), accountID, op).Scan(&state)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var commits, aborts int
	if err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT
 (SELECT COUNT(1) FROM envelope_receipts r JOIN secret_envelopes e ON e.envelope_id = r.envelope_id WHERE e.account_id = ? AND r.operation_id = ? AND r.receipt_type = 'vault_commit'),
 (SELECT COUNT(1) FROM envelope_receipts r JOIN secret_envelopes e ON e.envelope_id = r.envelope_id WHERE e.account_id = ? AND r.operation_id = ? AND r.receipt_type = 'abort' AND r.receipt_seq = 1)`),
		accountID, op, accountID, op).Scan(&commits, &aborts); err != nil {
		return "", err
	}
	switch {
	case commits > 0:
		return "committed", nil
	case aborts > 0:
		return "failed", nil
	}
	return "expired", nil
}

func (v vaultStore) MirrorLease(ctx context.Context, l *Lease) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		now := time.Now().UTC()
		res, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE checkout_leases SET state = ?, close_reason = ?, updated_at = ? WHERE request_id = ? AND account_id = ? AND state <> 'closed'`),
			l.State, l.CloseReason, now, l.RequestID, l.AccountID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 1 {
			return nil
		}
		var have string
		err = tx.QueryRowContext(ctx, v.s.rebind(`SELECT state FROM checkout_leases WHERE request_id = ?`), l.RequestID).Scan(&have)
		if err == nil {
			if have == l.State {
				return nil // a closed lease reported closed again
			}
			return ErrConflict // closed leases never reopen
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO checkout_leases (request_id, account_id, broker_id, secret_version, state, close_reason, opened_at, expires_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`),
			l.RequestID, l.AccountID, l.BrokerID, int64(l.SecretVersion), l.State, l.CloseReason, l.OpenedAt.UTC(), l.ExpiresAt.UTC(), now)
		if err != nil {
			return ErrConflict // the one-open-lease index, or a race on the same request
		}
		return nil
	})
}

func (v vaultStore) GetLease(ctx context.Context, requestID string) (*Lease, error) {
	var l Lease
	var ver int64
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT request_id, account_id, broker_id, secret_version, state, close_reason, opened_at, expires_at FROM checkout_leases WHERE request_id = ?`), requestID).
		Scan(&l.RequestID, &l.AccountID, &l.BrokerID, &ver, &l.State, &l.CloseReason, &l.OpenedAt, &l.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	l.SecretVersion = uint64(ver)
	return &l, err
}

func (v vaultStore) TxMailbox(ctx context.Context, requestID string) (*TxMail, error) {
	var m TxMail
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT challenge, purpose, delivery, result FROM access_transactions WHERE request_id = ?`), requestID).
		Scan(&m.Challenge, &m.Purpose, &m.Delivery, &m.Result)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &m, err
}

func (v vaultStore) SetTxMailbox(ctx context.Context, requestID string, m *TxMail) error {
	_, err := v.s.db.ExecContext(ctx, v.s.rebind(`UPDATE access_transactions SET
 challenge = CASE WHEN ? <> '' THEN ? ELSE challenge END,
 purpose = CASE WHEN ? <> '' THEN ? ELSE purpose END,
 delivery = CASE WHEN ? <> '' THEN ? ELSE delivery END,
 result = CASE WHEN ? <> '' THEN ? ELSE result END
 WHERE request_id = ?`), m.Challenge, m.Challenge, m.Purpose, m.Purpose, m.Delivery, m.Delivery, m.Result, m.Result, requestID)
	return err
}

func (v vaultStore) TxAccount(ctx context.Context, requestID string) (string, error) {
	var a string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT account_id FROM access_transactions WHERE request_id = ?`), requestID).Scan(&a)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return a, err
}
