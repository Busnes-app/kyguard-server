package migrations

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/testdb"
	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// stepped opens the test database for migrating one version at a time: q rebinds ? for
// PostgreSQL, exec runs a statement, and runThrough applies the registry up to version.
func stepped(t *testing.T) (db *sql.DB, q func(string) string, exec func(string, ...any), runThrough func(int) error) {
	cfg := testdb.Config(t)
	driverName := "sqlite"
	if cfg.Driver == "postgres" {
		driverName = "pgx"
	}
	var err error
	db, err = sql.Open(driverName, cfg.DSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	q = func(query string) string {
		if cfg.Driver != "postgres" {
			return query
		}
		for i := 1; strings.Contains(query, "?"); i++ {
			query = strings.Replace(query, "?", "$"+strconv.Itoa(i), 1)
		}
		return query
	}
	exec = func(query string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q(query), args...); err != nil {
			t.Fatal(err)
		}
	}
	all := registry
	t.Cleanup(func() { registry = all })
	runThrough = func(version int) error {
		for i, m := range all {
			if m.Version == version {
				registry = all[:i+1]
			}
		}
		return Run(ctx, db, cfg.Driver)
	}
	return db, q, exec, runThrough
}

// Sessions from before migration 6 carry no sid, so no back-channel logout could end
// them: migration 7 drops those SSO sessions, keeps local sign-ins, and keeps SSO
// sessions issued with a sid after migration 6. Pending SSO pairings, which would mint
// a session without a sid, go too.
func TestMigration7DropsUnreachableSSOSessions(t *testing.T) {
	ctx := context.Background()
	db, q, exec, step := stepped(t)
	runThrough := func(version int) {
		t.Helper()
		if err := step(version); err != nil {
			t.Fatal(err)
		}
	}

	now := time.Now().UTC()
	runThrough(5)
	for _, u := range []struct{ id, provider string }{{"usr_local", "local"}, {"usr_sso", "kysignon"}} {
		exec(`INSERT INTO users (id, username, sso_provider, sso_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, u.id, u.id, u.provider, u.id, now, now)
		exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`, "legacy_"+u.id, u.id, now, now.Add(time.Hour))
	}
	runThrough(6)
	exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, sso_sid) VALUES (?, ?, ?, ?, ?)`, "with_sid", "usr_sso", now, now.Add(time.Hour), "sid-1")
	for _, user := range []string{"usr_local", "usr_sso"} {
		exec(`INSERT INTO device_pairings (secret, user_id, status, created_at, expires_at, authenticated_at) VALUES (?, ?, 'pending', ?, ?, ?)`, "pair_"+user, user, now, now.Add(90*time.Second), now)
	}
	runThrough(7)
	for secret, want := range map[string]int{"pair_usr_local": 1, "pair_usr_sso": 0} {
		var got int
		if err := db.QueryRowContext(ctx, q(`SELECT COUNT(1) FROM device_pairings WHERE secret = ?`), secret).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("after migration 7, pairing %s: got %d rows, want %d", secret, got, want)
		}
	}

	for token, want := range map[string]int{"legacy_usr_local": 1, "legacy_usr_sso": 0, "with_sid": 1} {
		var got int
		if err := db.QueryRowContext(ctx, q(`SELECT COUNT(1) FROM sessions WHERE token_hash = ?`), token).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("after migration 7, session %s: got %d rows, want %d", token, got, want)
		}
	}

	runThrough(8)
	if _, err := db.ExecContext(ctx, "SELECT 1 FROM device_pairings"); err == nil {
		t.Error("after migration 8, device_pairings still exists")
	}
}

// Before migration 13 one subject could sit under two providers. Every legacy row gets an
// empty issuer, so the unique identity index covers only issued rows: the migration applies,
// the start refuses the unissued rows with its repair steps, and the index then refuses
// giving both rows the same issuer.
func TestMigration13KeepsLegacySubjectCollisions(t *testing.T) {
	db, q, exec, step := stepped(t)
	if err := step(12); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, provider := range []string{"scim", "kysignon"} {
		exec(`INSERT INTO users (id, username, sso_provider, sso_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, "usr_"+provider, provider, provider, "same-subject", now, now)
	}
	if err := step(13); err != nil {
		t.Fatalf("migration 13 over a legacy subject collision: %v", err)
	}
	exec(`UPDATE users SET sso_issuer = ? WHERE id = ?`, "https://idp.test", "usr_scim")
	if _, err := db.ExecContext(context.Background(), q(`UPDATE users SET sso_issuer = ? WHERE id = ?`), "https://idp.test", "usr_kysignon"); err == nil {
		t.Fatal("two accounts took the same (issuer, subject)")
	}
}

// Migration 13: an SSO session from before it has no issuer, so no issuer-keyed back-channel
// logout could end it. It is deleted; a local session stays.
func TestMigration13DropsSessionsNoLogoutCouldEnd(t *testing.T) {
	db, q, exec, step := stepped(t)
	if err := step(12); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	exec(`INSERT INTO users (id, username, sso_provider, sso_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, "usr_sso", "sso", "kysignon", "sub", now, now)
	exec(`INSERT INTO users (id, username, sso_provider, sso_subject, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)`, "usr_local", "local", "local", "", now, now)
	exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at, sso_sid) VALUES (?, ?, ?, ?, ?)`, "sso_with_sid", "usr_sso", now, now.Add(time.Hour), "sid-1")
	exec(`INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`, "local", "usr_local", now, now.Add(time.Hour))
	if err := step(13); err != nil {
		t.Fatal(err)
	}
	var kept []string
	rows, err := db.Query(q(`SELECT token_hash FROM sessions ORDER BY token_hash`))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		_ = rows.Scan(&h)
		kept = append(kept, h)
	}
	if len(kept) != 1 || kept[0] != "local" {
		t.Fatalf("sessions after migration 13: %v, want only the local one", kept)
	}
}

// Migrations run in registry order, and files append theirs in file-name order: a file that
// sorts before another but holds lower versions must fail here, not reorder history.
func TestRegistryIsAscending(t *testing.T) {
	for i := 1; i < len(registry); i++ {
		if registry[i].Version <= registry[i-1].Version {
			t.Fatalf("migration %d (%s) follows %d (%s)", registry[i].Version, registry[i].Name, registry[i-1].Version, registry[i-1].Name)
		}
	}
}
