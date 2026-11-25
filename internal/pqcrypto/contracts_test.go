package pqcrypto

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Consumers of the contract vectors. State comes only from context.json.

type contractFixture struct {
	ctx contextFile
}

func loadContext(t *testing.T) contractFixture {
	b, err := os.ReadFile(filepath.Join(vectorDir, "context.json"))
	if err != nil {
		t.Fatal(err)
	}
	var c contextFile
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	return contractFixture{c}
}

func (f contractFixture) trust(t *testing.T) *Trust {
	t.Helper()
	tr, err := NewTrust(f.ctx.Bundle, f.ctx.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range f.ctx.Manifests {
		if _, err := tr.Accept(m); err != nil {
			t.Fatalf("context manifest: %v", err)
		}
	}
	return tr
}

// contractFiles lists the contract vector files; vectorOps holds operations added by other
// files.
var (
	contractFiles = []string{"bootstrap.json", "custodian_set.json", "recovery_key.json", "pool.json", "policy.json",
		"key_enrollment.json", "target.json"}
	vectorOps = map[string]func(*testing.T, *Trust, objVector) ([]byte, Digest, error){}
)

// runVector performs the vector's operation and returns the canonical bytes and digest of
// the object when accepted.
func runVector(t *testing.T, f contractFixture, v objVector) ([]byte, Digest, error) {
	p := v.Params
	if v.Op == "bundle" {
		tr, err := NewTrust(v.Object, p.Pinned)
		if err != nil {
			return nil, Digest{}, err
		}
		c, _ := canonical.Canonicalize(v.Object)
		return c, tr.fingerprint, nil
	}
	if v.Op == "target" {
		_, d, err := DecodeTargetDescriptor(v.Object)
		c, _ := canonical.Canonicalize(v.Object)
		return c, d, err
	}
	tr := f.trust(t)
	for _, m := range p.Prior {
		if _, err := tr.Accept(m); err != nil {
			t.Fatalf("prior manifest: %v", err)
		}
	}
	switch v.Op {
	case "accept":
		r, err := tr.Accept(v.Object)
		if err != nil {
			return nil, Digest{}, err
		}
		return canon(v.Object), r.Digest, nil
	default:
		if op, ok := vectorOps[v.Op]; ok {
			return op(t, tr, v)
		}
	}
	t.Fatalf("%s: unknown op %q", v.Name, v.Op)
	return nil, Digest{}, nil
}

func canon(b []byte) []byte {
	c, _ := canonical.Canonicalize(b)
	return c
}

func TestVectorContracts(t *testing.T) {
	f := loadContext(t)
	for _, file := range contractFiles {
		for _, v := range load[objVector](t, file) {
			c, d, err := runVector(t, f, v)
			check(t, file+": "+v.Name, v.Verdict, err)
			if err == nil && v.Canonical != "" && (string(c) != v.Canonical || d.Hex() != v.Digest) {
				t.Errorf("%s: %s: canonical or digest differs", file, v.Name)
			}
		}
	}
}
