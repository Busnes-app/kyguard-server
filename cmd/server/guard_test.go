package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

func guardConfig(t *testing.T) (*config.Config, store.Store) {
	t.Helper()
	db := testdb.Config(t)
	cfg := &config.Config{Database: db}
	cfg.Database.DataDir = t.TempDir()
	st, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return cfg, st
}

func TestImportBundleChecksTheFingerprint(t *testing.T) {
	_, st := guardConfig(t)
	d := pqtest.New(t)
	path := filepath.Join(t.TempDir(), "bundle.json")
	if err := os.WriteFile(path, d.Bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var out bytes.Buffer
	if err := runImportBundle(ctx, st, []string{"--bundle", path, "--fingerprint", string(pqtest.New(t).Fingerprint)}, &out); err == nil {
		t.Fatal("imported under another fingerprint")
	}
	if _, err := st.Guard().Bundle(ctx); err == nil {
		t.Fatal("a refused bundle was stored")
	}
	if err := runImportBundle(ctx, st, []string{"--bundle", path, "--fingerprint", strings.ToUpper(string(d.Fingerprint))}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), string(d.Fingerprint)) {
		t.Fatalf("output %q", out.String())
	}
	other := pqtest.New(t)
	path2 := filepath.Join(t.TempDir(), "other.json")
	os.WriteFile(path2, other.Bundle, 0o600)
	if err := runImportBundle(ctx, st, []string{"--bundle", path2, "--fingerprint", string(other.Fingerprint)}, &out); err == nil {
		t.Fatal("a second deployment replaced the trust root")
	}
}

func TestGuardInitCreatesTheCAOnce(t *testing.T) {
	cfg, _ := guardConfig(t)
	var out bytes.Buffer
	if err := runGuardInit(cfg, &out); err != nil {
		t.Fatal(err)
	}
	ca, err := brokerproto.LoadCA(cfg.Database.DataDir)
	if err != nil || !strings.Contains(out.String(), string(ca.SHA256())) {
		t.Fatalf("%v %q", err, out.String())
	}
	if err := runGuardInit(cfg, &out); err == nil {
		t.Fatal("init replaced the broker CA")
	}
	if fi, err := os.Stat(filepath.Join(cfg.Database.DataDir, brokerproto.CAKeyFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file %v %v", fi, err)
	}
}

// §9.4 rule 3, §13 Phase 0 acceptance test 13: a broker CA other than the one paired brokers
// pinned refuses the start.
func TestStartRefusesABrokerCAThePairedBrokersDidNotPin(t *testing.T) {
	cfg, st := guardConfig(t)
	ctx := context.Background()
	ca, err := brokerproto.CreateCA(cfg.Database.DataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkBrokerCA(ctx, cfg, st); err != nil {
		t.Fatalf("no brokers yet: %v", err)
	}
	g := st.Guard()
	now := time.Now().UTC()
	if err := g.CreatePool(ctx, &store.BrokerPool{ID: "p", Name: "p", CreatedAt: now}, nil); err != nil {
		t.Fatal(err)
	}
	g.CreatePairingToken(ctx, &store.PairingToken{TokenHash: "t", PoolID: "p", CreatedBy: "a", CreatedAt: now, ExpiresAt: now.Add(time.Minute)}, nil)
	if err := g.ClaimPairing(ctx, "t", now, &store.Broker{ID: "b", CertSHA256: "c", CASHA256: string(ca.SHA256()), SigKeyID: "s", EncKeyID: "e", Version: "0.1.0"}, "i", nil); err != nil {
		t.Fatal(err)
	}
	if err := checkBrokerCA(ctx, cfg, st); err != nil {
		t.Fatalf("matching CA: %v", err)
	}
	// Replace the CA files with another CA, as a restore from the wrong capsule would.
	other := t.TempDir()
	if _, err := brokerproto.CreateCA(other); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{brokerproto.CACertFile, brokerproto.CAKeyFile} {
		os.Remove(filepath.Join(cfg.Database.DataDir, f))
		b, _ := os.ReadFile(filepath.Join(other, f))
		os.WriteFile(filepath.Join(cfg.Database.DataDir, f), b, 0o600)
	}
	if err := checkBrokerCA(ctx, cfg, st); err == nil || !strings.Contains(err.Error(), "not the CA paired brokers pinned") {
		t.Fatalf("mismatched CA: %v", err)
	}
	// Paired brokers and no CA at all is refused too.
	for _, f := range []string{brokerproto.CACertFile, brokerproto.CAKeyFile} {
		os.Remove(filepath.Join(cfg.Database.DataDir, f))
	}
	if err := checkBrokerCA(ctx, cfg, st); err == nil {
		t.Fatal("missing CA with paired brokers started")
	}
}
