package migrations

// The auth stack's migrations that must follow the broker stack's (100 and up) take versions
// from 200.
func init() {
	// Intents for external effects (spec §9.3), on the table migration 100 created: outcome
	// holds a noted completion record, so a failed append is not lost; failed is a known
	// refusal; recovery_pairing is a KyRecovery pairing claim (pairing is a broker's). SQLite
	// cannot change a CHECK in place, so the table is rebuilt, rows kept.
	registry = append(registry, dialects(200, "kyguard_intents_outcome", `
CREATE TABLE operation_intents_v2 (
    operation_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('pairing', 'recovery_pairing', 'deposit', 'pin')),
    subject TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending', 'complete', 'failed', 'outcome_unknown', 'superseded')),
    outcome TEXT NOT NULL DEFAULT '',
    created_at {{ts}} NOT NULL,
    updated_at {{ts}} NOT NULL
);
INSERT INTO operation_intents_v2 (operation_id, kind, subject, state, created_at, updated_at)
    SELECT operation_id, kind, subject, state, created_at, updated_at FROM operation_intents;
DROP TABLE operation_intents;
ALTER TABLE operation_intents_v2 RENAME TO operation_intents;
CREATE INDEX idx_operation_intents_state ON operation_intents(kind, state);`))
}
