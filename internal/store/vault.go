package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrLocked means another operation holds the account's rotation lock.
var ErrLocked = errors.New("account rotation lock is held by another operation")

// ErrTooLarge refuses a chain or descriptor over its size cap.
var ErrTooLarge = errors.New("record over its size limit")

// MaxChain bounds an envelope with all its receipts, and MaxDescriptor a target descriptor,
// in canonical bytes, so one chain and its descriptor always fit one sync reply.
// MaxEnvelope leaves room in the chain for commit_target and a release carrying a wrap for
// each of up to pqcrypto.MaxStandingRecipients standing recipients (or one abort or
// vault_commit), so a stored envelope can always be finished (security reviews of #10, #15).
const (
	MaxChain      = 256 << 10
	MaxDescriptor = 64 << 10
	MaxEnvelope   = MaxChain - 96<<10
)

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
	PoolAccounts(ctx context.Context, poolID, after string, limit int) ([]*Account, error)
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
	// marks the run of every envelope a new abort receipt names aborted, sets
	// current_envelope_id when current is non-empty and above the current version, moves
	// op's run to runState when non-empty, and applies lock to the lock held by op. One
	// transaction (§4.3 rule 7, §4.5). Receipts that are all already stored change nothing
	// else: a delayed duplicate never rewinds derived state.
	Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, lock LockAction) error
	// ReserveEnrollment moves the account's lock to op as a reserved enrollment with a new
	// version, keeping the holder it displaces (a stuck rotation) to restore later. It is
	// allowed when no lock is held or the account is quarantined (§4.5 step 1); a retry by
	// op returns the same version. An op that already ended, or whose transaction (requestID)
	// is already stored, is refused with ErrConflict.
	ReserveEnrollment(ctx context.Context, accountID, op, requestID string, now time.Time, ttl time.Duration) (uint64, error)
	// AcceptEnrollment moves op's reservation from reserved to accepted by compare-and-swap;
	// ErrConflict if it expired or is not op's. Accepting twice is a no-op.
	AcceptEnrollment(ctx context.Context, accountID, op string, now time.Time) error
	// ExpireEnrollments releases every reservation still reserved past its expiry and
	// restores the holder it displaced. An accepted reservation never expires.
	ExpireEnrollments(ctx context.Context, now time.Time) (int, error)
	// EnrollmentState is reserved or accepted while op holds the lock, then committed or
	// failed by its receipts, else expired.
	EnrollmentState(ctx context.Context, accountID, op string) (string, error)
	// PutTx stores a relayed transaction once.
	PutTx(ctx context.Context, requestID, accountID, actionType, digest string, raw []byte) error
	// QueuePush stores a Control Plane push for a broker until expires, for whichever
	// replica holds the broker's channel; TakePushes removes and returns, oldest first, at
	// most limit unexpired pushes for the broker. A push is taken once.
	QueuePush(ctx context.Context, p *Push) error
	TakePushes(ctx context.Context, brokerID string, limit int, now time.Time) ([]*Push, error)
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

// PoolAccounts returns at most limit of the pool's accounts with IDs above after, by ID.
func (v vaultStore) PoolAccounts(ctx context.Context, poolID, after string, limit int) ([]*Account, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT `+accountCols+` FROM accounts WHERE pool_id = ? AND id > ? ORDER BY id LIMIT ?`), poolID, after, limit)
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
	// The digest names the content, so a stored row is the same descriptor: concurrent
	// identical stores are all no-ops (Guide on #10, "Concurrent retries").
	_, err := v.s.db.ExecContext(ctx, v.s.rebind(`INSERT INTO target_descriptors (digest, account_id, descriptor, created_at) VALUES (?, ?, ?, ?) ON CONFLICT DO NOTHING`),
		digest, accountID, string(raw), time.Now().UTC())
	return err
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

// notEnded refuses, with ErrConflict, an operation that already has receipts on the account.
func (v vaultStore) notEnded(ctx context.Context, tx *sql.Tx, accountID, op string) error {
	var ended int
	if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COUNT(1) FROM envelope_receipts r JOIN secret_envelopes e ON e.envelope_id = r.envelope_id
 WHERE r.operation_id = ? AND e.account_id = ?`), op, accountID).Scan(&ended); err != nil {
		return err
	}
	if ended > 0 {
		return ErrConflict
	}
	return nil
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
		// An operation that already ended never reserves again: a late retry would take a new
		// version and a lock nothing releases (PR Reviewer Guide on #10).
		if err := v.notEnded(ctx, tx, accountID, op); err != nil {
			return err
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
	if len(e.Envelope) > MaxEnvelope {
		return ErrTooLarge
	}
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		// The account lock comes first, so a concurrent identical retry sees the first
		// one's row and succeeds (PR Reviewer Guide on #10).
		if _, err := v.lockAccount(ctx, tx, e.AccountID); err != nil {
			return err
		}
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
		// The account lock comes first, so a concurrent identical retry sees the first
		// one's row and succeeds (PR Reviewer Guide on #10).
		if _, err := v.lockAccount(ctx, tx, r.AccountID); err != nil {
			return err
		}
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

func (v vaultStore) Complete(ctx context.Context, op, accountID string, rs []*StoredReceipt, current, runState string, lock LockAction) error {
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
			if added && r.ReceiptType == "abort" {
				if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_runs SET state = 'aborted', updated_at = ?
WHERE account_id = ? AND state <> 'release_authorized' AND secret_version = (SELECT secret_version FROM secret_envelopes WHERE envelope_id = ?)`),
					time.Now().UTC(), accountID, r.EnvelopeID); err != nil {
					return err
				}
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
			// Only a mutating run becomes unknown (§4.2): a late status never undoes an outcome.
			if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE rotation_runs SET state = ?, updated_at = ? WHERE operation_id = ? AND account_id = ?
 AND (state = 'mutating' OR ? <> 'write_outcome_unknown')`), runState, time.Now().UTC(), op, accountID, runState); err != nil {
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
	return v.reinstate(ctx, tx, accountID, prev, prevVer)
}

// reinstate gives the lock back to the holder an enrollment displaced, if there was one.
func (v vaultStore) reinstate(ctx context.Context, tx *sql.Tx, accountID string, prev sql.NullString, prevVer sql.NullInt64) error {
	if !prev.Valid {
		return nil
	}
	_, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO rotation_locks (account_id, operation_id, secret_version, created_at) VALUES (?, ?, ?, ?)`),
		accountID, prev.String, prevVer.Int64, time.Now().UTC())
	return err
}

func (v vaultStore) ReserveEnrollment(ctx context.Context, accountID, op, requestID string, now time.Time, ttl time.Duration) (uint64, error) {
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
		// A completed enrollment's retry takes no new version or lock (PR Reviewer Guide
		// "Retry Idempotency" on #15), and neither does one whose transaction was already
		// submitted: the stored transaction is immutable and names the old version
		// ("Unusable Retry").
		if err := v.notEnded(ctx, tx, accountID, op); err != nil {
			return err
		}
		var submitted int
		if err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COUNT(1) FROM access_transactions WHERE request_id = ?`), requestID).Scan(&submitted); err != nil {
			return err
		}
		if submitted > 0 {
			return ErrConflict
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
		version = highest + 1
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

// expire restores the displaced holder of an account's expired reservation. The state and
// deadline check is the delete itself, so an acceptance that commits first keeps its lock
// (PostgreSQL rechecks the WHERE after waiting on the accepting row).
func (v vaultStore) expire(ctx context.Context, tx *sql.Tx, accountID string, now time.Time) error {
	var prev sql.NullString
	var prevVer sql.NullInt64
	err := tx.QueryRowContext(ctx, v.s.rebind(`DELETE FROM rotation_locks WHERE account_id = ? AND kind = 'enrollment' AND state = 'reserved' AND expires_at <= ?
RETURNING previous_operation_id, previous_secret_version`), accountID, now).Scan(&prev, &prevVer)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return v.reinstate(ctx, tx, accountID, prev, prevVer)
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

// Push is one queued Control Plane push.
type Push struct {
	BrokerID  string
	Type      string
	Body      []byte
	ExpiresAt time.Time
}

func (v vaultStore) QueuePush(ctx context.Context, p *Push) error {
	id, err := uuid.NewV7() // time-ordered, so pushes go out oldest first
	if err != nil {
		return err
	}
	_, err = v.s.db.ExecContext(ctx, v.s.rebind(`INSERT INTO broker_outbox (id, broker_id, type, body, expires_at) VALUES (?, ?, ?, ?, ?)`),
		id.String(), p.BrokerID, p.Type, string(p.Body), p.ExpiresAt.UTC())
	return err
}

func (v vaultStore) TakePushes(ctx context.Context, brokerID string, limit int, now time.Time) ([]*Push, error) {
	var out []*Push
	err := v.s.inTx(ctx, func(tx *sql.Tx) error {
		out = nil
		if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM broker_outbox WHERE expires_at <= ?`), now.UTC()); err != nil {
			return err
		}
		// One DELETE ... RETURNING: concurrent takers never both get a row.
		rows, err := tx.QueryContext(ctx, v.s.rebind(`DELETE FROM broker_outbox WHERE id IN (SELECT id FROM broker_outbox WHERE broker_id = ? ORDER BY id LIMIT ?)
 RETURNING id, type, body, expires_at`), brokerID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		ids := map[*Push]string{}
		for rows.Next() {
			var p Push
			var id, body string
			if err := rows.Scan(&id, &p.Type, &body, &p.ExpiresAt); err != nil {
				return err
			}
			p.BrokerID, p.Body = brokerID, []byte(body)
			ids[&p] = id
			out = append(out, &p)
		}
		slices.SortFunc(out, func(a, b *Push) int { return cmp.Compare(ids[a], ids[b]) })
		return rows.Err()
	})
	return out, err
}

func (v vaultStore) PutTx(ctx context.Context, requestID, accountID, actionType, digest string, raw []byte) error {
	// Insert-or-keep, then compare: two identical submissions racing on PostgreSQL both
	// succeed, and a different transaction under the same request ID is a conflict (Guide
	// on #15, "Concurrent retries").
	if _, err := v.s.db.ExecContext(ctx, v.s.rebind(`INSERT INTO access_transactions (request_id, account_id, action_type, digest, tx, created_at) VALUES (?, ?, ?, ?, ?, ?)
 ON CONFLICT DO NOTHING`), requestID, accountID, actionType, digest, string(raw), time.Now().UTC()); err != nil {
		return err
	}
	// No conflict target: request_id and digest are both unique, and PostgreSQL raises a
	// concurrent clash on a unique index the target does not name.
	var have string
	err := v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT tx FROM access_transactions WHERE request_id = ?`), requestID).Scan(&have)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrConflict // the digest belongs to another request
	} else if err != nil {
		return err
	}
	if have != string(raw) {
		return ErrConflict
	}
	return nil
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
