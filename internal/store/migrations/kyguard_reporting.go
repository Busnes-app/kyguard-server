package migrations

// KyGuard reporting migrations take versions from 300, after the auth stack's 200 (spec
// §8.2, §9.2). Nothing is seeded:
// migrate-postgres and the PostgreSQL snapshot refuse non-empty target tables.
func init() {
	registry = append(registry, dialects(300, "kyguard_attributes", `
CREATE TABLE attribute_definitions (
    id TEXT PRIMARY KEY,
    entity TEXT NOT NULL CHECK (entity IN ('account', 'user')),
    key TEXT NOT NULL,
    label TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('string', 'enum')),
    enum_values TEXT NOT NULL DEFAULT '[]',
    source TEXT NOT NULL CHECK (source IN ('admin', 'scim')),
    created_at {{ts}} NOT NULL,
    UNIQUE (entity, key)
);
CREATE TABLE attribute_values (
    definition_id TEXT NOT NULL REFERENCES attribute_definitions(id) ON DELETE CASCADE,
    entity_id TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at {{ts}} NOT NULL,
    UNIQUE (definition_id, entity_id)
);
CREATE INDEX idx_attribute_values_entity ON attribute_values(entity_id);`),
		dialects(301, "kyguard_policy_drafts", `
CREATE TABLE policy_drafts (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL UNIQUE REFERENCES accounts(id),
    epoch BIGINT NOT NULL CHECK (epoch > 0),
    digest TEXT NOT NULL,
    object TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at {{ts}} NOT NULL,
    updated_at {{ts}} NOT NULL
);`))
}
