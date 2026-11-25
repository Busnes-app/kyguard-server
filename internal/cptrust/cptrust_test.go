package cptrust_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

func setup(t *testing.T) (store.Store, *pqtest.Deployment) {
	t.Helper()
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := pqtest.New(t)
	if err := st.Guard().ImportBundle(context.Background(), &store.BootstrapBundle{DeploymentID: string(d.ID), Fingerprint: string(d.Fingerprint), Bundle: d.Bundle}, "host"); err != nil {
		t.Fatal(err)
	}
	return st, d
}

func brokerMember(t *testing.T) pqcrypto.BrokerMember {
	t.Helper()
	sig, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	b := &pqtest.Broker{ID: pqtest.UUID(), Sig: sig, Enc: enc, CertSHA256: pqcrypto.HexID("aa00000000000000000000000000000000000000000000000000000000000000")}
	return b.Member(pqcrypto.StatusActive)
}

func countAudit(t *testing.T, st store.Store, action string) int {
	t.Helper()
	recs, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range recs {
		if r.Action == action {
			n++
		}
	}
	return n
}

func TestNoBundleRefusesEverything(t *testing.T) {
	st, err := store.Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := cptrust.New(st).View(context.Background(), func(*pqcrypto.Trust) error { return nil }); !errors.Is(err, cptrust.ErrNoBundle) {
		t.Fatalf("got %v", err)
	}
}

func TestSubmitVerifiesPersistsAndIsSeenByAReplica(t *testing.T) {
	st, d := setup(t)
	ctx := context.Background()
	a, b := cptrust.New(st), cptrust.New(st)
	pool := pqtest.UUID()
	m := brokerMember(t)
	p1 := d.Pool(t, pool, 1, []pqcrypto.BrokerMember{m}, nil)
	if _, added, err := a.Submit(ctx, p1, "u", ""); err != nil || !added {
		t.Fatalf("submit: %v %v", added, err)
	}
	if _, added, err := a.Submit(ctx, p1, "u", ""); err != nil || added {
		t.Fatalf("resubmit is idempotent: %v %v", added, err)
	}
	// b was built before the submit and catches up from the database.
	if err := b.View(ctx, func(tr *pqcrypto.Trust) error {
		if tr.Pool(pool) == nil || tr.Pool(pool).Active().BrokerID != m.BrokerID {
			return errors.New("replica does not see the pool")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// b appends epoch 2; a catches up before its own next write instead of forking the log.
	m.Status = pqcrypto.StatusRevoked
	p2 := d.Pool(t, pool, 2, []pqcrypto.BrokerMember{m}, nil)
	if _, _, err := b.Submit(ctx, p2, "u", ""); err != nil {
		t.Fatal(err)
	}
	other := pqtest.UUID()
	if _, added, err := a.Submit(ctx, d.Pool(t, other, 1, []pqcrypto.BrokerMember{brokerMember(t)}, nil), "u", ""); err != nil || !added {
		t.Fatalf("stale writer: %v %v", added, err)
	}
	ms, err := st.Guard().Manifests(ctx, 0)
	if err != nil || len(ms) != 3 {
		t.Fatalf("stored %d %v", len(ms), err)
	}
	if n := countAudit(t, st, "trust.manifest_accepted"); n != 3 {
		t.Fatalf("%d acceptance records", n)
	}
}

// §3.7 rule 1 on the Control Plane: rollback and same-epoch forks are refused, forks alert.
func TestSubmitRefusesRollbackAndEquivocation(t *testing.T) {
	st, d := setup(t)
	ctx := context.Background()
	c := cptrust.New(st)
	pool := pqtest.UUID()
	m := brokerMember(t)
	if _, _, err := c.Submit(ctx, d.Pool(t, pool, 2, []pqcrypto.BrokerMember{m}, nil), "u", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Submit(ctx, d.Pool(t, pool, 1, []pqcrypto.BrokerMember{m}, nil), "u", ""); !errors.Is(err, pqcrypto.ErrRollback) {
		t.Fatalf("rollback: %v", err)
	}
	fork := m
	fork.MTLSCertSHA256 = "bb00000000000000000000000000000000000000000000000000000000000000"
	if _, _, err := c.Submit(ctx, d.Pool(t, pool, 2, []pqcrypto.BrokerMember{fork}, nil), "u", ""); !errors.Is(err, pqcrypto.ErrEquivocation) {
		t.Fatalf("fork: %v", err)
	}
	if n := countAudit(t, st, "trust.equivocation"); n != 1 {
		t.Fatalf("%d equivocation alerts", n)
	}
	// Signed by a different deployment's custodians.
	if _, _, err := c.Submit(ctx, pqtest.New(t).Pool(t, pool, 3, []pqcrypto.BrokerMember{m}, nil), "u", ""); err == nil {
		t.Fatal("foreign manifest accepted")
	}
	if ms, _ := st.Guard().Manifests(ctx, 0); len(ms) != 1 {
		t.Fatalf("refused manifests were stored: %d", len(ms))
	}
}

// A manifest that could never fit a broker channel frame is refused at upload, before it
// is parsed or stored (decision 61).
func TestSubmitRefusesAnOversizedManifest(t *testing.T) {
	st, _ := setup(t)
	raw := make([]byte, cptrust.MaxManifest+1)
	if _, _, err := cptrust.New(st).Submit(context.Background(), raw, "custodian", ""); !errors.Is(err, cptrust.ErrTooLarge) {
		t.Fatalf("oversized manifest: %v", err)
	}
	if ms, _ := st.Guard().Manifests(context.Background(), 0); len(ms) != 0 {
		t.Fatalf("stored %d manifests", len(ms))
	}
}
