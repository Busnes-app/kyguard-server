package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

func guardStoreFor(t *testing.T) (*SQLStore, GuardStore) {
	t.Helper()
	st, err := Open(context.Background(), testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	s := st.(*SQLStore)
	return s, s.Guard()
}

func TestImportBundleOnce(t *testing.T) {
	_, g := guardStoreFor(t)
	ctx := context.Background()
	if _, err := g.Bundle(ctx); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty: %v", err)
	}
	b := &BootstrapBundle{DeploymentID: "d", Fingerprint: "f1", Bundle: []byte("{}")}
	if err := g.ImportBundle(ctx, b, "host"); err != nil {
		t.Fatal(err)
	}
	if err := g.ImportBundle(ctx, b, "host"); err != nil {
		t.Fatalf("same bundle again: %v", err)
	}
	if err := g.ImportBundle(ctx, &BootstrapBundle{DeploymentID: "d", Fingerprint: "f2", Bundle: []byte("{}")}, "host"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("other bundle: %v", err)
	}
}

func TestAppendManifestNeedsTheNextSeq(t *testing.T) {
	_, g := guardStoreFor(t)
	ctx := context.Background()
	m := func(seq int64) *TrustManifest {
		return &TrustManifest{Seq: seq, Type: "pool", ScopeID: "p", Epoch: uint64(seq), Digest: "d", Manifest: []byte("{}")}
	}
	if err := g.AppendManifest(ctx, m(2), nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("gap: %v", err)
	}
	if err := g.AppendManifest(ctx, m(1), nil); err != nil {
		t.Fatal(err)
	}
	if err := g.AppendManifest(ctx, m(1), nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale writer: %v", err)
	}
	got, err := g.Manifests(ctx, 0)
	if err != nil || len(got) != 1 || got[0].Seq != 1 {
		t.Fatalf("manifests %v %v", got, err)
	}
}

func seedPool(t *testing.T, g GuardStore, token string, expires time.Time) {
	t.Helper()
	ctx := context.Background()
	if _, err := g.GetPool(ctx, "p1"); errors.Is(err, ErrNotFound) {
		if err := g.CreatePool(ctx, &BrokerPool{ID: "p1", Name: "pool", CreatedAt: time.Now().UTC()}, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := g.CreatePairingToken(ctx, &PairingToken{TokenHash: token, PoolID: "p1", CreatedBy: "u", CreatedAt: time.Now().UTC(), ExpiresAt: expires}, nil); err != nil {
		t.Fatal(err)
	}
}

func broker(id string) *Broker {
	return &Broker{ID: id, CertSHA256: "cert-" + id, CASHA256: "ca", SigKeyID: "s", EncKeyID: "e", Version: "0.1.0"}
}

func TestClaimPairingIsOneTimeAndExpires(t *testing.T) {
	_, g := guardStoreFor(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedPool(t, g, "live", now.Add(10*time.Minute))
	seedPool(t, g, "old", now.Add(-time.Second))
	if err := g.ClaimPairing(ctx, "live", now, broker("b1"), "i1", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPairing(ctx, "live", now, broker("b2"), "i2", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second claim: %v", err)
	}
	if err := g.ClaimPairing(ctx, "old", now, broker("b3"), "i3", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired: %v", err)
	}
	if err := g.ClaimPairing(ctx, "unknown", now, broker("b4"), "i4", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown: %v", err)
	}
	if b, err := g.GetBroker(ctx, "b1"); err != nil || b.PoolID != "p1" {
		t.Fatalf("broker %v %v", b, err)
	}
	if _, err := g.GetBroker(ctx, "b2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("refused claim left a broker: %v", err)
	}
	if i, err := g.GetIntent(ctx, "i1"); err != nil || i.State != IntentPending || i.Subject != "b1" {
		t.Fatalf("intent %v %v", i, err)
	}
}

func TestClaimPairingRacesHaveOneWinner(t *testing.T) {
	_, g := guardStoreFor(t)
	seedPool(t, g, "tok", time.Now().UTC().Add(time.Minute))
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Go(func() {
			errs[i] = g.ClaimPairing(context.Background(), "tok", time.Now().UTC(), broker(fmt.Sprint("b", i)), fmt.Sprint("i", i), nil)
		})
	}
	wg.Wait()
	won := 0
	for _, err := range errs {
		switch {
		case err == nil:
			won++
		case errors.Is(err, ErrNotFound):
		default:
			// SQLite serializes; PostgreSQL may report a serialization error instead.
			t.Logf("claim: %v", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d claims won", won)
	}
}

func TestExpirePendingIntentsLeavesYoungOnes(t *testing.T) {
	s, g := guardStoreFor(t)
	ctx := context.Background()
	now := time.Now().UTC()
	seedPool(t, g, "a", now.Add(time.Hour))
	seedPool(t, g, "b", now.Add(time.Hour))
	if err := g.ClaimPairing(ctx, "a", now.Add(-time.Hour), broker("b1"), "old", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.ClaimPairing(ctx, "b", now, broker("b2"), "young", nil); err != nil {
		t.Fatal(err)
	}
	n, err := g.ExpirePendingIntents(ctx, "pairing", now.Add(-time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("expired %d %v", n, err)
	}
	for id, want := range map[string]string{"old": IntentOutcomeUnknown, "young": IntentPending} {
		if i, err := g.GetIntent(ctx, id); err != nil || i.State != want {
			t.Fatalf("%s: %v %v", id, i, err)
		}
	}
	var audited int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(1) FROM audit_records WHERE action = 'pairing.outcome_unknown'`).Scan(&audited); err != nil || audited != 1 {
		t.Fatalf("audited %d %v", audited, err)
	}
	if err := g.SetIntentState(ctx, "old", IntentPending, IntentComplete); !errors.Is(err, ErrConflict) {
		t.Fatalf("an unknown outcome is not completed by a late writer: %v", err)
	}
}
