package migrations

func init() {
	registry = append(registry, dialects(302, "kyguard_browser_keys", `
CREATE TABLE browser_keys (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    subject TEXT NOT NULL,
    enrollment TEXT NOT NULL,
    sealed TEXT NOT NULL
);`))
}
