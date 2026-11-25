package store

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"
)

// ErrLocked means another operation holds the account's rotation lock.
var ErrLocked = errors.New("account rotation lock is held by another operation")

// ErrTooLarge refuses a chain or descriptor over its size cap.
var ErrTooLarge = errors.New("record over its size limit")

// MaxChain bounds an envelope with all its receipts, and MaxDescriptor a target descriptor,
// in canonical bytes, so one chain and its descriptor always fit one sync reply.
const (
	MaxChain      = 256 << 10
	MaxDescriptor = 64 << 10
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
	// ChainsAfter returns at most limit envelopes of the account above version after, in
	// version order, with their receipts.
	ChainsAfter(ctx context.Context, accountID string, after uint64, limit int) ([]*StoredChain, error)
	// OpenChains returns at most limit envelopes above version after and at or below upTo
	// that are the account's current envelope or have no abort, release or vault_commit
	// receipt, in version order, with their receipts.
	OpenChains(ctx context.Context, accountID string, after, upTo uint64, limit int) ([]*StoredChain, error)
	// Chain returns one envelope of the account with its receipts, or ErrNotFound.
	Chain(ctx context.Context, accountID, envelopeID string) (*StoredChain, error)
	// Complete appends receipts by compare-and-swap (a byte-identical re-append is a no-op),
	// sets current_envelope_id when current is non-empty and above the current version,
	// moves op's run to runState when non-empty and, when release is true, deletes the lock
	// held by op. One transaction (§4.3 rule 7). Receipts that are all already stored change
	// nothing else: a delayed duplicate never rewinds derived state.
	Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, release bool) error
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
	if len(raw) > MaxDescriptor {
		return ErrTooLarge
	}
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
	if len(e.Envelope) > MaxChain {
		return ErrTooLarge
	}
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
	return v.chainsWhere(ctx, `e.account_id = ? ORDER BY e.secret_version`, accountID)
}

func (v vaultStore) ChainsAfter(ctx context.Context, accountID string, after uint64, limit int) ([]*StoredChain, error) {
	return v.chainsWhere(ctx, `e.account_id = ? AND e.secret_version > ? ORDER BY e.secret_version LIMIT ?`, accountID, int64(min(after, 1<<63-1)), limit)
}

func (v vaultStore) OpenChains(ctx context.Context, accountID string, after, upTo uint64, limit int) ([]*StoredChain, error) {
	return v.chainsWhere(ctx, `e.account_id = ? AND e.secret_version > ? AND e.secret_version <= ? AND (e.envelope_id = (SELECT current_envelope_id FROM accounts WHERE id = e.account_id)
 OR NOT EXISTS (SELECT 1 FROM envelope_receipts t WHERE t.envelope_id = e.envelope_id AND t.receipt_type IN ('abort', 'release', 'vault_commit'))) ORDER BY e.secret_version LIMIT ?`,
		accountID, int64(min(after, 1<<63-1)), int64(min(upTo, 1<<63-1)), limit)
}

func (v vaultStore) Chain(ctx context.Context, accountID, envelopeID string) (*StoredChain, error) {
	cs, err := v.chainsWhere(ctx, `e.account_id = ? AND e.envelope_id = ?`, accountID, envelopeID)
	if err == nil && len(cs) == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return cs[0], nil
}

// chainsWhere loads the envelopes `FROM secret_envelopes e WHERE <where>` (which may end in
// ORDER BY and LIMIT), then the receipts of exactly those envelopes.
func (v vaultStore) chainsWhere(ctx context.Context, where string, args ...any) ([]*StoredChain, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT e.envelope_id, e.account_id, e.secret_version, e.envelope_kind, e.digest, e.envelope FROM secret_envelopes e WHERE `+where), args...)
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
	// Receipts by envelope ID, not by re-running where: an envelope stored between the two
	// reads must not shift a LIMIT window. Chunks stay under every driver's parameter limit.
	for chunk := range slices.Chunk(out, 500) {
		ids := make([]any, len(chunk))
		for i, c := range chunk {
			ids[i] = c.Envelope.EnvelopeID
		}
		q := `SELECT envelope_id, receipt_seq, receipt_type, operation_id, digest, prev_receipt_hash, receipt FROM envelope_receipts WHERE envelope_id IN (?` +
			strings.Repeat(", ?", len(ids)-1) + `) ORDER BY envelope_id, receipt_seq`
		if err := v.receiptsInto(ctx, byID, q, ids); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (v vaultStore) receiptsInto(ctx context.Context, byID map[string]*StoredChain, q string, args []any) error {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(q), args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var r StoredReceipt
		var seq int64
		var raw string
		if err := rows.Scan(&r.EnvelopeID, &seq, &r.ReceiptType, &r.OperationID, &r.Digest, &r.PrevReceiptHash, &raw); err != nil {
			return err
		}
		r.ReceiptSeq, r.Receipt = uint64(seq), []byte(raw)
		c := byID[r.EnvelopeID]
		c.Receipts = append(c.Receipts, &r)
	}
	return rows.Err()
}

// appendReceipt is the §3.5 compare-and-swap: seq must be head+1 and prev the head hash. It
// reports whether the receipt is new.
func (v vaultStore) appendReceipt(ctx context.Context, tx *sql.Tx, r *StoredReceipt) (bool, error) {
	var have string
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT receipt FROM envelope_receipts WHERE envelope_id = ? AND receipt_seq = ?`), r.EnvelopeID, int64(r.ReceiptSeq)).Scan(&have)
	if err == nil {
		if have == string(r.Receipt) {
			return false, nil // a retry after restart
		}
		return false, ErrConflict
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	var headSeq, size int64
	var headHash sql.NullString
	if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COALESCE(MAX(receipt_seq), 0), (SELECT digest FROM envelope_receipts WHERE envelope_id = ? ORDER BY receipt_seq DESC LIMIT 1),
 COALESCE(SUM(LENGTH(receipt)), 0) + (SELECT LENGTH(envelope) FROM secret_envelopes WHERE envelope_id = ?) FROM envelope_receipts WHERE envelope_id = ?`),
		r.EnvelopeID, r.EnvelopeID, r.EnvelopeID).Scan(&headSeq, &headHash, &size); err != nil {
		return false, err
	}
	prev := zeroHash
	if headHash.Valid {
		prev = headHash.String
	}
	if r.ReceiptSeq != uint64(headSeq)+1 || r.PrevReceiptHash != prev {
		return false, ErrConflict
	}
	if size+int64(len(r.Receipt)) > MaxChain {
		return false, ErrTooLarge
	}
	_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO envelope_receipts (envelope_id, receipt_seq, receipt_type, operation_id, digest, prev_receipt_hash, receipt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
		r.EnvelopeID, int64(r.ReceiptSeq), r.ReceiptType, r.OperationID, r.Digest, r.PrevReceiptHash, string(r.Receipt), time.Now().UTC())
	return err == nil, err
}

const zeroHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (v vaultStore) Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, release bool) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := v.lockAccount(ctx, tx, accountID); err != nil {
			return err
		}
		fresh := len(rs) == 0
		for _, r := range rs {
			var owner string
			if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT account_id FROM secret_envelopes WHERE envelope_id = ?`), r.EnvelopeID).Scan(&owner); err != nil || owner != accountID {
				if err == nil || errors.Is(err, sql.ErrNoRows) {
					err = ErrNotFound
				}
				return err
			}
			added, err := v.appendReceipt(ctx, tx, r)
			if err != nil {
				return err
			}
			fresh = fresh || added
		}
		if !fresh {
			return nil
		}
		if current != "" {
			// The current envelope is the highest released version (§3.5), never a lower one.
			if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET current_envelope_id = ? WHERE id = ? AND COALESCE((SELECT secret_version FROM secret_envelopes
 WHERE envelope_id = accounts.current_envelope_id), 0) < (SELECT secret_version FROM secret_envelopes WHERE envelope_id = ?)`), current, accountID, current); err != nil {
				return err
			}
		}
		if runState != "" {
			if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_runs SET state = ?, updated_at = ? WHERE operation_id = ? AND account_id = ?`), runState, time.Now().UTC(), op, accountID); err != nil {
				return err
			}
		}
		if release {
			// A delete by operation_id: it never removes another operation's lock (§4.3 rule 7).
			if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM rotation_locks WHERE account_id = ? AND operation_id = ?`), accountID, op); err != nil {
				return err
			}
		}
		return nil
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
