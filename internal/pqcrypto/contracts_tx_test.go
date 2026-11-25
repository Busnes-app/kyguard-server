package pqcrypto

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

func init() {
	vectorOps["tx"] = opTx
	vectorOps["pop"] = opPop
	vectorOps["envelope"] = opEnvelope
	vectorOps["receipt"] = opReceipt
	vectorOps["extends"] = opExtends
}

func decodeTx(t *testing.T, raw json.RawMessage) *AccessTransaction {
	t.Helper()
	if raw == nil {
		return nil
	}
	var tx AccessTransaction
	if _, err := canonical.Decode(raw, &tx); err != nil {
		t.Fatal(err)
	}
	return &tx
}

func counter(t *testing.T, s string) Counter {
	t.Helper()
	if s == "" {
		return 0
	}
	c, err := ParseCounter(s)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// chainOf verifies a historical envelope and appends receipts as history.
func chainOf(t *testing.T, tr *Trust, env json.RawMessage, receipts []json.RawMessage) *Chain {
	t.Helper()
	e, err := tr.VerifyEnvelope(env, EnvelopeContext{})
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	c := NewChain(e)
	for _, r := range receipts {
		if _, err := tr.Append(c, r, ReceiptContext{}); err != nil {
			t.Fatalf("prior receipt: %v", err)
		}
	}
	return c
}

func opTx(t *testing.T, tr *Trust, v objVector) ([]byte, Digest, error) {
	p := v.Params
	now, err := time.Parse(TimeLayout, p.Now)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[UUID]bool{}
	for _, s := range p.Seen {
		seen[s] = true
	}
	c := TxContext{BrokerID: p.BrokerID, Now: now, Seen: func(u UUID) bool { return seen[u] },
		CandidateDigest: p.CandidateDigest, CandidateVersion: counter(t, p.CandidateVersion), HighestVersion: counter(t, p.HighestVersion)}
	if p.Current != nil {
		c.Current = &CurrentEnvelope{p.Current.EnvelopeID, counter(t, p.Current.SecretVersion), p.Current.ReceiptHead}
	}
	_, d, err := tr.VerifyTx(v.Object, c)
	return canon(v.Object), d, err
}

func opPop(t *testing.T, tr *Trust, v objVector) ([]byte, Digest, error) {
	p := v.Params
	tx := decodeTx(t, p.Tx)
	td, err := ObjDigest(tx)
	if err != nil {
		t.Fatal(err)
	}
	pop, err := VerifyPoP(v.Object, tx, td, p.Challenge, p.Purpose)
	if err != nil {
		return nil, Digest{}, err
	}
	d, _ := ObjDigest(pop)
	return canon(v.Object), d, nil
}

func opEnvelope(t *testing.T, tr *Trust, v objVector) ([]byte, Digest, error) {
	p := v.Params
	e, err := tr.VerifyEnvelope(v.Object, EnvelopeContext{New: p.New, Enroll: decodeTx(t, p.EnrollTx)})
	if err != nil {
		return nil, Digest{}, err
	}
	return canon(v.Object), e.Digest, nil
}

func opReceipt(t *testing.T, tr *Trust, v objVector) ([]byte, Digest, error) {
	p := v.Params
	c := chainOf(t, tr, p.Envelope, p.Receipts)
	r, err := tr.Append(c, v.Object, ReceiptContext{New: p.New, StandingRelease: decodeTx(t, p.StandingRelease)})
	if err != nil {
		return nil, Digest{}, err
	}
	d, _ := ObjDigest(r)
	if c.Head != d.Hex() {
		t.Errorf("%s: chain head not advanced", v.Name)
	}
	return canon(v.Object), d, nil
}

func opExtends(t *testing.T, tr *Trust, v objVector) ([]byte, Digest, error) {
	p := v.Params
	local := chainOf(t, tr, p.Envelope, p.Receipts)
	remote := chainOf(t, tr, p.Envelope, p.Remote)
	return nil, Digest{}, ChainExtends(local.Heads, remote.Heads)
}

func TestCurrentEnvelopeRule(t *testing.T) {
	ch := func(kind string, v Counter, released, vaultCommitted, aborted bool) *Chain {
		return &Chain{Envelope: &VerifiedEnvelope{SecretEnvelope: &SecretEnvelope{EnvelopeKind: kind, SecretVersion: v}},
			Released: released, VaultCommitted: vaultCommitted, Aborted: aborted}
	}
	managed := []*Chain{
		ch(KindManaged, 3, true, false, false),
		ch(KindManaged, 4, false, true, false),  // enrolled baseline
		ch(KindManaged, 5, false, false, false), // rotation committed at the target only
		ch(KindManaged, 6, false, false, true),  // aborted
	}
	if got := CurrentEnvelopeOf(managed); got != managed[1] {
		t.Fatalf("managed current is v%d, want v4", got.Envelope.SecretVersion)
	}
	vaulted := []*Chain{ch(KindVaulted, 1, false, true, false), ch(KindVaulted, 2, true, false, false)}
	if got := CurrentEnvelopeOf(vaulted); got != vaulted[0] {
		t.Fatalf("vaulted current is v%d, want v1: only vault_commit counts", got.Envelope.SecretVersion)
	}
	if CurrentEnvelopeOf(managed[2:]) != nil {
		t.Fatal("no qualifying chain must give no current envelope")
	}
}
