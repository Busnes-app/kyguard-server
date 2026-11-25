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
CREATE INDEX idx_operation_intents_state ON operation_intents(state);`))
}

// dialects builds one migration from shared DDL; {{ts}} is the timestamp type.
func dialects(version int, name, ddl string) Migration {
	return Migration{
		Version:  version,
		Name:     name,
		SQLite:   strings.ReplaceAll(ddl, "{{ts}}", "DATETIME"),
		Postgres: strings.ReplaceAll(ddl, "{{ts}}", "TIMESTAMPTZ"),
	}
}
