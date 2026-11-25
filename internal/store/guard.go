package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// GuardStore holds KyGuard's Control Plane trust and broker state (spec §4.1, §9.2).
type GuardStore interface {
	// Bundle returns the imported bootstrap bundle; ErrNotFound before import.
	Bundle(ctx context.Context) (*BootstrapBundle, error)
	// ImportBundle stores the bundle once; ErrAlreadyExists if another one is stored.
	// Re-importing the same fingerprint is a no-op.
	ImportBundle(ctx context.Context, b *BootstrapBundle, actor string) error
	// Manifests returns verified manifests with seq > after, in acceptance order.
	Manifests(ctx context.Context, after int64) ([]*TrustManifest, error)
	// ManifestsPage returns at most limit of them.
	ManifestsPage(ctx context.Context, after int64, limit int) ([]*TrustManifest, error)
	// AppendManifest stores the next verified manifest; m.Seq must be the current maximum
	// plus one, otherwise ErrConflict (another writer appended first: catch up and retry).
	AppendManifest(ctx context.Context, m *TrustManifest, audit *AuditRecord) error

	CreatePool(ctx context.Context, p *BrokerPool, audit *AuditRecord) error
	GetPool(ctx context.Context, id string) (*BrokerPool, error)
	CreatePairingToken(ctx context.Context, t *PairingToken, audit *AuditRecord) error
	// ClaimPairing consumes an unexpired, unconsumed token by hash and, in the same
	// transaction, records the broker and a pending pairing intent. ErrNotFound when the
	// token is unknown, consumed or expired.
	ClaimPairing(ctx context.Context, tokenHash string, now time.Time, b *Broker, intentID string, audit *AuditRecord) error
	GetBroker(ctx context.Context, id string) (*Broker, error)

	// SetIntentState moves an intent from one state to another; ErrConflict if it is not
	// in from.
	SetIntentState(ctx context.Context, id, from, to string) error
	// ExpirePendingIntents marks every pending intent of kind created before cutoff
	// outcome_unknown (startup reconciliation, §9.3) and audits each one.
	ExpirePendingIntents(ctx context.Context, kind string, cutoff time.Time) (int, error)
	// BrokerCAHashes lists the distinct CA hashes paired brokers pinned.
	BrokerCAHashes(ctx context.Context) ([]string, error)
	GetIntent(ctx context.Context, id string) (*OperationIntent, error)
}

// Intent states (§9.3).
const (
	IntentPending        = "pending"
	IntentComplete       = "complete"
	IntentOutcomeUnknown = "outcome_unknown"
)

// BootstrapBundle is the deployment trust root as imported by the operator.
type BootstrapBundle struct {
	DeploymentID string
	Fingerprint  string
	Bundle       []byte
	ImportedAt   time.Time
}

// TrustManifest is one Custodian-signed manifest the Control Plane verified.
type TrustManifest struct {
	Seq        int64
	Type       string
	ScopeID    string
	Epoch      uint64
	Digest     string
	Manifest   []byte
	AcceptedAt time.Time
}

// BrokerPool groups the accounts one broker serves.
type BrokerPool struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// PairingToken is stored by the SHA-256 of its secret only.
type PairingToken struct {
	TokenHash string
	PoolID    string
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// Broker is a paired broker. Pairing alone grants nothing: a broker works only once a
// Custodian-signed pool manifest lists it as active.
type Broker struct {
	ID         string
	PoolID     string
	CertSHA256 string
	CASHA256   string
	SigKeyID   string
	EncKeyID   string
	Version    string
	PairedAt   time.Time
}

// OperationIntent is a durable record of an external effect (§9.3).
type OperationIntent struct {
	OperationID string
	Kind        string
	Subject     string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type guardStore struct{ s *SQLStore }

func (s *SQLStore) Guard() GuardStore { return guardStore{s} }

// inTx runs fn in one transaction and commits only if it succeeds.
func (s *SQLStore) inTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// auditTx writes an audit record inside the caller's transaction, so the change and its
// record commit or roll back together (§9.3). The chained append replaces this insert.
func (s *SQLStore) auditTx(ctx context.Context, tx *sql.Tx, r *AuditRecord) error {
	if r == nil {
		return nil
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	_, err := tx.ExecContext(ctx, s.rebind(`INSERT INTO audit_records (user_id, action, resource, details, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`),
		r.UserID, r.Action, r.Resource, r.Details, r.IPAddress, r.CreatedAt)
	return err
}

func (g guardStore) Bundle(ctx context.Context) (*BootstrapBundle, error) {
	var b BootstrapBundle
	var raw string
	err := g.s.db.QueryRowContext(ctx, `SELECT deployment_id, fingerprint, bundle, imported_at FROM bootstrap_bundles WHERE id = 1`).
		Scan(&b.DeploymentID, &b.Fingerprint, &raw, &b.ImportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	b.Bundle = []byte(raw)
	return &b, nil
}

func (g guardStore) ImportBundle(ctx context.Context, b *BootstrapBundle, actor string) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		var fp string
		err := tx.QueryRowContext(ctx, `SELECT fingerprint FROM bootstrap_bundles WHERE id = 1`).Scan(&fp)
		switch {
		case err == nil && fp == b.Fingerprint:
			return nil
		case err == nil:
			return ErrAlreadyExists
		case !errors.Is(err, sql.ErrNoRows):
			return err
		}
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO bootstrap_bundles (id, deployment_id, fingerprint, bundle, imported_at) VALUES (1, ?, ?, ?, ?)`),
			b.DeploymentID, b.Fingerprint, string(b.Bundle), time.Now().UTC()); err != nil {
			return err
		}
		return g.s.auditTx(ctx, tx, &AuditRecord{UserID: actor, Action: "trust.bundle_imported", Resource: "deployment:" + b.DeploymentID, Details: "fingerprint=" + b.Fingerprint})
	})
}

func (g guardStore) Manifests(ctx context.Context, after int64) ([]*TrustManifest, error) {
	return g.manifests(ctx, ``, after)
}

func (g guardStore) ManifestsPage(ctx context.Context, after int64, limit int) ([]*TrustManifest, error) {
	return g.manifests(ctx, ` LIMIT ?`, after, max(limit, 0))
}

func (g guardStore) manifests(ctx context.Context, limit string, args ...any) ([]*TrustManifest, error) {
	rows, err := g.s.db.QueryContext(ctx, g.s.rebind(`SELECT seq, type, scope_id, epoch, digest, manifest, accepted_at FROM trust_manifests WHERE seq > ? ORDER BY seq`+limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*TrustManifest
	for rows.Next() {
		var m TrustManifest
		var raw string
		var epoch int64
		if err := rows.Scan(&m.Seq, &m.Type, &m.ScopeID, &epoch, &m.Digest, &raw, &m.AcceptedAt); err != nil {
			return nil, err
		}
		m.Epoch, m.Manifest = uint64(epoch), []byte(raw)
		out = append(out, &m)
	}
	return out, rows.Err()
}

func (g guardStore) AppendManifest(ctx context.Context, m *TrustManifest, audit *AuditRecord) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		if g.s.driver == "postgres" {
			if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(5, hashtext('kyguard:trust_manifests'))`); err != nil {
				return err
			}
		}
		var max int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM trust_manifests`).Scan(&max); err != nil {
			return err
		}
		if m.Seq != max+1 {
			return ErrConflict
		}
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO trust_manifests (seq, type, scope_id, epoch, digest, manifest, accepted_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			m.Seq, m.Type, m.ScopeID, int64(m.Epoch), m.Digest, string(m.Manifest), time.Now().UTC()); err != nil {
			return err
		}
		return g.s.auditTx(ctx, tx, audit)
	})
}

func (g guardStore) CreatePool(ctx context.Context, p *BrokerPool, audit *AuditRecord) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, g.s.rebind(`SELECT COUNT(1) FROM broker_pools WHERE id = ? OR name = ?`), p.ID, p.Name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrAlreadyExists
		}
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO broker_pools (id, name, created_at) VALUES (?, ?, ?)`), p.ID, p.Name, p.CreatedAt); err != nil {
			return err
		}
		return g.s.auditTx(ctx, tx, audit)
	})
}

func (g guardStore) GetPool(ctx context.Context, id string) (*BrokerPool, error) {
	var p BrokerPool
	err := g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT id, name, created_at FROM broker_pools WHERE id = ?`), id).Scan(&p.ID, &p.Name, &p.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &p, err
}

func (g guardStore) CreatePairingToken(ctx context.Context, t *PairingToken, audit *AuditRecord) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO pairing_tokens (token_hash, pool_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`),
			t.TokenHash, t.PoolID, t.CreatedBy, t.CreatedAt, t.ExpiresAt); err != nil {
			return err
		}
		return g.s.auditTx(ctx, tx, audit)
	})
}

func (g guardStore) ClaimPairing(ctx context.Context, tokenHash string, now time.Time, b *Broker, intentID string, audit *AuditRecord) error {
	return g.s.inTx(ctx, func(tx *sql.Tx) error {
		var pool string
		err := tx.QueryRowContext(ctx, g.s.rebind(`UPDATE pairing_tokens SET consumed_at = ?, broker_id = ?
WHERE token_hash = ? AND consumed_at IS NULL AND expires_at > ? RETURNING pool_id`), now, b.ID, tokenHash, now).Scan(&pool)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		b.PoolID, b.PairedAt = pool, now
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO brokers (id, pool_id, cert_sha256, ca_sha256, sig_key_id, enc_key_id, version, paired_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			b.ID, b.PoolID, b.CertSHA256, b.CASHA256, b.SigKeyID, b.EncKeyID, b.Version, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, g.s.rebind(`INSERT INTO operation_intents (operation_id, kind, subject, state, created_at, updated_at) VALUES (?, 'pairing', ?, 'pending', ?, ?)`),
			intentID, b.ID, now, now); err != nil {
			return err
		}
		return g.s.auditTx(ctx, tx, audit)
	})
}

func (g guardStore) GetBroker(ctx context.Context, id string) (*Broker, error) {
	var b Broker
	err := g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT id, pool_id, cert_sha256, ca_sha256, sig_key_id, enc_key_id, version, paired_at FROM brokers WHERE id = ?`), id).
		Scan(&b.ID, &b.PoolID, &b.CertSHA256, &b.CASHA256, &b.SigKeyID, &b.EncKeyID, &b.Version, &b.PairedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &b, err
}

func (g guardStore) SetIntentState(ctx context.Context, id, from, to string) error {
	res, err := g.s.db.ExecContext(ctx, g.s.rebind(`UPDATE operation_intents SET state = ?, updated_at = ? WHERE operation_id = ? AND state = ?`), to, time.Now().UTC(), id, from)
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
}

func (g guardStore) ExpirePendingIntents(ctx context.Context, kind string, cutoff time.Time) (int, error) {
	n := 0
	err := g.s.inTx(ctx, func(tx *sql.Tx) error {
		// One statement moves only rows still pending, so a replica's sweep or a pairing
		// handler that settled one first keeps its outcome, and each row is audited once.
		rows, err := tx.QueryContext(ctx, g.s.rebind(`UPDATE operation_intents SET state = 'outcome_unknown', updated_at = ?
WHERE kind = ? AND state = 'pending' AND created_at < ? RETURNING operation_id, subject`), time.Now().UTC(), kind, cutoff.UTC())
		if err != nil {
			return err
		}
		var ids, subjects []string
		for rows.Next() {
			var id, subject string
			if err := rows.Scan(&id, &subject); err != nil {
				rows.Close()
				return err
			}
			ids, subjects = append(ids, id), append(subjects, subject)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for i, id := range ids {
			if err := g.s.auditTx(ctx, tx, &AuditRecord{UserID: "system", Action: kind + ".outcome_unknown", Resource: "operation:" + id, Details: "subject=" + subjects[i]}); err != nil {
				return err
			}
		}
		n = len(ids)
		return nil
	})
	return n, err
}

func (g guardStore) GetIntent(ctx context.Context, id string) (*OperationIntent, error) {
	var o OperationIntent
	err := g.s.db.QueryRowContext(ctx, g.s.rebind(`SELECT operation_id, kind, subject, state, created_at, updated_at FROM operation_intents WHERE operation_id = ?`), id).
		Scan(&o.OperationID, &o.Kind, &o.Subject, &o.State, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &o, err
}

func (g guardStore) BrokerCAHashes(ctx context.Context) ([]string, error) {
	rows, err := g.s.db.QueryContext(ctx, `SELECT DISTINCT ca_sha256 FROM brokers ORDER BY ca_sha256`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
