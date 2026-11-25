package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/capsule"
	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/backup"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func sealFixture(t *testing.T, service string) (string, []string) {
	t.Helper()
	return sealFiles(t, service, []recoveryclient.File{{Path: "data/x.db", Data: []byte("payload"), Mode: 0600}})
}

func sealFiles(t *testing.T, service string, files []recoveryclient.File) (string, []string) {
	t.Helper()
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(priv, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	key := recoveryclient.RecoveryKey{Public: priv.Public(), Threshold: 2, TotalShares: 3}
	payload := recoveryclient.Payload{ServiceName: service, AppVersion: "1.0.0", Files: files}
	raw, _, err := recoveryclient.Seal(payload, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "x.kycap")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	// Non-consecutive indices: {1,2} would let an XOR-shaped bug pass.
	return path, []string{shares[0].String(), shares[2].String()}
}

func TestRestoreExtractsWithTwoShares(t *testing.T) {
	path, shares := sealFixture(t, "busnes_app")
	target := t.TempDir()
	var out bytes.Buffer
	if err := restore(path, target, "busnes_app", shares, &out); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(target, "data", "x.db"))
	if err != nil || string(got) != "payload" {
		t.Fatalf("restored file: %q %v", got, err)
	}
	if !strings.Contains(out.String(), "busnes_app") {
		t.Fatalf("manifest not printed: %s", out.String())
	}
}

func TestRestoreRefusesAnotherService(t *testing.T) {
	path, shares := sealFixture(t, "someone_else")
	err := restore(path, t.TempDir(), "busnes_app", shares, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "someone_else") {
		t.Fatalf("got %v, want a service-name refusal naming the capsule's service", err)
	}
}

func TestRestoreRefusesTheWrongKit(t *testing.T) {
	path, _ := sealFixture(t, "busnes_app")
	_, otherShares := sealFixture(t, "busnes_app")
	err := restore(path, t.TempDir(), "busnes_app", otherShares, &bytes.Buffer{})
	if !errors.Is(err, capsule.ErrWrongRecoveryKey) {
		t.Fatalf("got %v, want ErrWrongRecoveryKey", err)
	}
}

func TestRestoreRefusesOneShare(t *testing.T) {
	path, shares := sealFixture(t, "busnes_app")
	if err := restore(path, t.TempDir(), "busnes_app", shares[:1], &bytes.Buffer{}); err == nil {
		t.Fatal("one share of a 2-of-3 kit was accepted")
	}
}

// A restored copy may be a drill beside the live server: it must not deposit on its own,
// even when the old server had a schedule saved. It also carries no session minted before
// the capsule and no replica fingerprint.
func TestRestoreTurnsScheduledDepositsOff(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ky_server.db")
	db, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at DATETIME NOT NULL);
INSERT INTO server_settings VALUES ('backup_interval_sec', '86400', '2026-01-01 00:00:00');
INSERT INTO server_settings VALUES ('replica_config_fingerprint', '{}', '2026-01-01 00:00:00');
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL);
INSERT INTO sessions VALUES ('a', 'u1'), ('b', 'u2');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path, shares := sealFiles(t, "busnes_app", []recoveryclient.File{{Path: "data/ky_server.db", Data: raw, Mode: 0600}})
	target := t.TempDir()
	var out bytes.Buffer
	if err := restore(path, target, "busnes_app", shares, &out); err != nil {
		t.Fatal(err)
	}
	for _, said := range []string{"Scheduled deposits are OFF", "Sessions deleted from the restored copy: 2", "Replica configuration record removed"} {
		if !strings.Contains(out.String(), said) {
			t.Fatalf("restore does not say %q: %s", said, out.String())
		}
	}
	db, err = sql.Open("sqlite", filepath.Join(target, "data", "ky_server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var v string
	if err := db.QueryRow(`SELECT value FROM server_settings WHERE key = 'backup_interval_sec'`).Scan(&v); err != nil || v != "0" {
		t.Fatalf("backup_interval_sec = %q, %v; want 0", v, err)
	}
	var sessions, fingerprints int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM sessions), (SELECT count(*) FROM server_settings WHERE key = 'replica_config_fingerprint')`).Scan(&sessions, &fingerprints); err != nil || sessions != 0 || fingerprints != 0 {
		t.Fatalf("restored copy keeps %d sessions and %d fingerprint rows (%v)", sessions, fingerprints, err)
	}
	entries, _ := os.ReadDir(filepath.Join(target, "data"))
	if len(entries) != 1 {
		t.Fatalf("restore left extra files beside the database: %v", entries)
	}
}

// Acceptance 13: a restore deletes every bearer credential minted before the capsule:
// sessions, CLI login codes and the broker pairing tokens not yet spent. A spent token is
// history (which broker it paired) and stays.
func TestRestoreDeletesEveryBearerCredential(t *testing.T) {
	src := filepath.Join(t.TempDir(), "ky_server.db")
	db, err := sql.Open("sqlite", src)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE server_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at DATETIME NOT NULL);
CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL);
INSERT INTO sessions VALUES ('a', 'u1');
CREATE TABLE cli_login_codes (code_hash TEXT PRIMARY KEY);
INSERT INTO cli_login_codes VALUES ('c1'), ('c2');
CREATE TABLE pairing_tokens (token_hash TEXT PRIMARY KEY, consumed_at DATETIME);
INSERT INTO pairing_tokens VALUES ('open', NULL), ('spent', '2026-01-01 00:00:00');`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	path, shares := sealFiles(t, "busnes_app", []recoveryclient.File{{Path: "data/ky_server.db", Data: raw, Mode: 0600}})
	target := t.TempDir()
	var out bytes.Buffer
	if err := restore(path, target, "busnes_app", shares, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "CLI login codes and outstanding broker pairing tokens deleted: 2 and 1") {
		t.Fatalf("restore output: %s", out.String())
	}
	db, err = sql.Open("sqlite", filepath.Join(target, "data", "ky_server.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var sessions, codes int
	var tokens string
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM sessions), (SELECT count(*) FROM cli_login_codes), (SELECT group_concat(token_hash) FROM pairing_tokens)`).Scan(&sessions, &codes, &tokens); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 || codes != 0 || tokens != "spent" {
		t.Fatalf("restored copy keeps %d sessions, %d CLI codes, pairing tokens %q", sessions, codes, tokens)
	}
}

// sqliteTexts returns, per table of a SQLite file, the sorted text of its rows; skip drops a
// table ("") or keeps only rows matching a condition.
func sqliteTexts(t *testing.T, path string, skip map[string]string) map[string]string {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tables []string
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations'`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		_ = rows.Scan(&name)
		tables = append(tables, name)
	}
	rows.Close()
	out := map[string]string{}
	for _, table := range tables {
		where := ""
		if cond, ok := skip[table]; ok {
			if cond == "" {
				continue
			}
			where = " WHERE " + cond
		}
		r, err := db.Query(`SELECT * FROM ` + table + where)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		cols, _ := r.Columns()
		var lines []string
		for r.Next() {
			vals := make([]sql.NullString, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := r.Scan(ptrs...); err != nil {
				t.Fatalf("%s: %v", table, err)
			}
			line := make([]string, len(vals))
			for i, v := range vals {
				line[i] = fmt.Sprintf("%v:%q", v.Valid, v.String)
			}
			lines = append(lines, strings.Join(line, ","))
		}
		r.Close()
		sort.Strings(lines)
		out[table] = strings.Join(lines, "\n")
	}
	return out
}

// Acceptance 13 on SQLite (PostgreSQL: TestPostgresBackupRestoreDrill): a seeded instance is
// collected, sealed and restored with two shares. Durable state matches, the audit chain
// verifies under the restored key, sessions are gone, the broker CA comes back, the restored
// copy passes startup and its break-glass admin signs in.
func TestSQLiteBackupRestoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	t.Setenv("KY_DATA_DIR", t.TempDir())
	t.Setenv("KY_DB_DRIVER", "sqlite")
	t.Setenv("KY_ENCRYPTION_KEY", strings.Repeat("cd", 32))
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Server.AppName = "busnes_app"
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	st := openStore(t, cfg)
	must(bootstrap(ctx, cfg, st))
	admin := newTestBreakGlass(t, cfg, st, "root")
	must(st.Sessions().CreateSession(ctx, &store.Session{TokenHash: "live-session", UserID: admin.ID, CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)}, admin.Hash))
	must(st.Audit().LogAudit(ctx, &store.AuditRecord{UserID: admin.ID, Action: "round.trip"}))
	_, err = st.Intents().Begin(ctx, "deposit", "busnes_app")
	must(err)
	must(st.Settings().SetSetting(ctx, "theme", "busnes"))
	// A real broker CA: the restored server loads it before it serves (prepareStart).
	_, err = brokerproto.CreateCA(cfg.Database.DataDir)
	must(err)
	caFiles := map[string][]byte{}
	for _, name := range []string{brokerproto.CAKeyFile, brokerproto.CACertFile} {
		caFiles[name], err = os.ReadFile(filepath.Join(cfg.Database.DataDir, name))
		must(err)
	}
	key, _, shares := throwawayKit(t)
	pinKey(t, cfg, st, key)

	payload, err := backup.Collect(ctx, cfg, st, appVersion)
	must(err)
	raw, _, err := recoveryclient.Seal(payload, key)
	must(err)
	capsulePath := filepath.Join(t.TempDir(), "rt.kycap")
	must(os.WriteFile(capsulePath, raw, 0600))
	target := t.TempDir()
	var out bytes.Buffer
	must(restore(capsulePath, target, "busnes_app", shares, &out))

	restoredDB := filepath.Join(target, "data", "ky_server.db")
	skip := map[string]string{"sessions": "", "server_settings": "key NOT IN ('backup_interval_sec', 'replica_config_fingerprint')"}
	before, after := sqliteTexts(t, filepath.Join(cfg.Database.DataDir, "ky_server.db"), skip), sqliteTexts(t, restoredDB, skip)
	if len(before) != len(after) {
		t.Errorf("restored schema has %d tables, source %d", len(after), len(before))
	}
	for table, text := range before {
		if after[table] != text {
			t.Errorf("table %s differs after the restore", table)
		}
	}
	for name, data := range caFiles {
		if got, err := os.ReadFile(filepath.Join(target, "data", name)); err != nil || !bytes.Equal(got, data) {
			t.Errorf("restored %s differs: %v", name, err)
		}
	}

	keyHex, err := os.ReadFile(filepath.Join(target, "data", "encryption.key"))
	must(err)
	restoredCfg := *cfg
	restoredCfg.Database.DataDir = filepath.Join(target, "data")
	restoredCfg.Database.DSN = restoredDB
	restoredCfg.Security.EncryptionKey, err = hex.DecodeString(strings.TrimSpace(string(keyHex)))
	must(err)
	restoredCfg.Database.AuditKey, err = config.AuditChainKey(restoredCfg.Security.EncryptionKey)
	must(err)
	restoredSt := openStore(t, &restoredCfg)
	must(restoredSt.Audit().VerifyAuditChain(ctx))
	if _, err := restoredSt.Sessions().GetSession(ctx, "live-session"); err == nil {
		t.Fatal("a session minted before the capsule survived the restore")
	}
	must(prepareStart(ctx, &restoredCfg, restoredSt))
	restoredCfg.Captcha.Provider = "none"
	srv := api.NewServer(&restoredCfg, restoredSt)
	body, _ := json.Marshal(map[string]string{"username": "root", "password": admin.Password, "totp_code": admin.Code(t)})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest("POST", "/api/auth/login", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("restored admin login: %d %s", w.Code, w.Body.String())
	}
}
