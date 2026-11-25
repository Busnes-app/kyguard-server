package migrations

import "strings"

// KyGuard broker migrations take versions from 100 so the Phase 0 stacks (12 and up) and
// the broker stack never collide; registry order is ascending either way.
func init() {
	registry = append(registry, dialects(100, "kyguard_brokers", `
CREATE TABLE bootstrap_bundles (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    deployment_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    bundle TEXT NOT NULL,
    imported_at {{ts}} NOT NULL
);
CREATE TABLE trust_manifests (
    seq BIGINT PRIMARY KEY CHECK (seq > 0),
    type TEXT NOT NULL,
    scope_id TEXT NOT NULL,
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    digest TEXT NOT NULL,
    manifest TEXT NOT NULL,
    accepted_at {{ts}} NOT NULL,
    UNIQUE (type, scope_id, epoch)
);
CREATE TABLE broker_pools (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at {{ts}} NOT NULL
);
CREATE TABLE brokers (
    id TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES broker_pools(id),
    cert_sha256 TEXT NOT NULL UNIQUE,
    ca_sha256 TEXT NOT NULL,
    sig_key_id TEXT NOT NULL,
    enc_key_id TEXT NOT NULL,
    version TEXT NOT NULL,
    paired_at {{ts}} NOT NULL
);
CREATE TABLE pairing_tokens (
    token_hash TEXT PRIMARY KEY,
    pool_id TEXT NOT NULL REFERENCES broker_pools(id),
    created_by TEXT NOT NULL,
    created_at {{ts}} NOT NULL,
    expires_at {{ts}} NOT NULL,
    consumed_at {{ts}},
    broker_id TEXT
);
CREATE TABLE operation_intents (
    operation_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('pairing', 'deposit', 'pin')),
    subject TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'outcome_unknown', 'superseded')),
    created_at {{ts}} NOT NULL,
    updated_at {{ts}} NOT NULL
);
CREATE INDEX idx_operation_intents_state ON operation_intents(state);`),
		dialects(101, "kyguard_vault", `
CREATE TABLE assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at {{ts}} NOT NULL
);
CREATE TABLE accounts (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    name TEXT NOT NULL,
    account_kind TEXT NOT NULL CHECK (account_kind IN ('managed', 'vaulted')),
    pool_id TEXT REFERENCES broker_pools(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'decommissioned')),
    owner_user_id TEXT REFERENCES users(id),
    current_envelope_id TEXT,
    min_password_age_seconds BIGINT,
    highest_secret_version BIGINT NOT NULL DEFAULT 0 CHECK (highest_secret_version >= 0),
    health TEXT NOT NULL DEFAULT '',
    health_reason TEXT NOT NULL DEFAULT '',
    created_at {{ts}} NOT NULL
);
CREATE TABLE target_descriptors (
    digest TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    descriptor TEXT NOT NULL,
    created_at {{ts}} NOT NULL
);
CREATE TABLE secret_envelopes (
    envelope_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    secret_version BIGINT NOT NULL CHECK (secret_version > 0),
    envelope_kind TEXT NOT NULL CHECK (envelope_kind IN ('managed', 'vaulted')),
    digest TEXT NOT NULL UNIQUE,
    envelope TEXT NOT NULL,
    created_at {{ts}} NOT NULL,
    UNIQUE (account_id, secret_version)
);
CREATE TABLE envelope_receipts (
    envelope_id TEXT NOT NULL REFERENCES secret_envelopes(envelope_id),
    receipt_seq BIGINT NOT NULL CHECK (receipt_seq > 0),
    receipt_type TEXT NOT NULL CHECK (receipt_type IN ('commit_target', 'abort', 'vault_commit', 'release', 'rewrap_user')),
    operation_id TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    prev_receipt_hash TEXT NOT NULL,
    receipt TEXT NOT NULL,
    created_at {{ts}} NOT NULL,
    PRIMARY KEY (envelope_id, receipt_seq)
);
CREATE TABLE rotation_locks (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id),
    operation_id TEXT NOT NULL,
    secret_version BIGINT NOT NULL CHECK (secret_version > 0),
    created_at {{ts}} NOT NULL
);
CREATE TABLE rotation_runs (
    operation_id TEXT NOT NULL,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    broker_id TEXT NOT NULL,
    secret_version BIGINT NOT NULL CHECK (secret_version > 0),
    intent TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('mutating', 'write_outcome_unknown', 'target_verified', 'release_authorized', 'aborted')),
    created_at {{ts}} NOT NULL,
    updated_at {{ts}} NOT NULL,
    PRIMARY KEY (account_id, operation_id)
);`),
		dialects(102, "kyguard_enrollment", `
ALTER TABLE rotation_locks ADD COLUMN kind TEXT NOT NULL DEFAULT 'rotation' CHECK (kind IN ('rotation', 'enrollment'));
ALTER TABLE rotation_locks ADD COLUMN state TEXT NOT NULL DEFAULT 'held' CHECK (state IN ('held', 'reserved', 'accepted'));
ALTER TABLE rotation_locks ADD COLUMN previous_operation_id TEXT;
ALTER TABLE rotation_locks ADD COLUMN previous_secret_version BIGINT;
ALTER TABLE rotation_locks ADD COLUMN expires_at {{ts}};
CREATE TABLE access_transactions (
    request_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    action_type TEXT NOT NULL,
    digest TEXT NOT NULL UNIQUE,
    tx TEXT NOT NULL,
    created_at {{ts}} NOT NULL
);
CREATE TABLE broker_outbox (
    id {{serial}},
    broker_id TEXT NOT NULL,
    type TEXT NOT NULL,
    body TEXT NOT NULL,
    expires_at {{ts}} NOT NULL
);
CREATE INDEX broker_outbox_broker ON broker_outbox (broker_id, id);`))
}

// dialects builds one migration from shared DDL; {{ts}} is the timestamp type.
func dialects(version int, name, ddl string) Migration {
	return Migration{
		Version:  version,
		Name:     name,
		SQLite:   strings.NewReplacer("{{ts}}", "DATETIME", "{{serial}}", "INTEGER PRIMARY KEY AUTOINCREMENT").Replace(ddl),
		Postgres: strings.NewReplacer("{{ts}}", "TIMESTAMPTZ", "{{serial}}", "BIGSERIAL PRIMARY KEY").Replace(ddl),
	}
}
