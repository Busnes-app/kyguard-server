package pqcrypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Consumers of testdata/vectors: each runs the code under test on the vector's inputs and
// checks the generator's stated verdict.

func load[T any](t *testing.T, name string) []T {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatal(err)
	}
	var vs []T
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) == 0 {
		t.Fatalf("%s has no vectors", name)
	}
	return vs
}

// verdict maps an error to its vector code.
func verdict(err error) string {
	if err == nil {
		return ok
	}
	var pe Error
	if errors.As(err, &pe) {
		return string(pe)
	}
	var ce canonical.Error
	if errors.As(err, &ce) {
		return string(ce)
	}
	return err.Error()
}

func check(t *testing.T, name, want string, err error) {
	t.Helper()
	if got := verdict(err); got != want {
		t.Errorf("%s: verdict %q, want %q", name, got, want)
	}
}

func TestVectorCanonical(t *testing.T) {
	for _, v := range load[canonicalVector](t, "canonical.json") {
		in, err := DecodeB64(v.InputB64)
		if err != nil {
			t.Fatal(err)
		}
		got, err := canonical.Canonicalize(in)
		check(t, v.Name, v.Verdict, err)
		if err == nil && string(got) != v.Canonical {
			t.Errorf("%s: canonical %s, want %s", v.Name, got, v.Canonical)
		}
	}
}

func TestVectorCounter(t *testing.T) {
	for _, v := range load[counterVector](t, "counter.json") {
		var c Counter
		_, err := canonical.Decode([]byte(v.JSON), &c)
		check(t, v.Name, v.Verdict, err)
		if err == nil && c.String() != v.Value {
			t.Errorf("%s: %s, want %s", v.Name, c, v.Value)
		}
		var s string
		if json.Unmarshal([]byte(v.JSON), &s) == nil {
			_, err := ParseCounter(s) // the parser alone, without the marshal-side cap
			check(t, v.Name+" (ParseCounter)", v.Verdict, err)
		}
	}
}

func TestVectorBase64(t *testing.T) {
	for _, v := range load[base64Vector](t, "base64url.json") {
		b, err := DecodeB64(v.Input)
		check(t, v.Name, v.Verdict, err)
		if err == nil && hex.EncodeToString(b) != v.BytesHx {
			t.Errorf("%s: %x, want %s", v.Name, b, v.BytesHx)
		}
	}
}

func TestVectorSigKeyID(t *testing.T) {
	for _, v := range load[sigKeyIDVector](t, "sig_key_id.json") {
		k, err := NewSigningKey(v.MLDSASeed, v.Ed25519Seed)
		if err != nil {
			t.Fatal(err)
		}
		pub := k.Public()
		if !bytes.Equal(pub.MLDSA65, v.SigPub.MLDSA65) || !bytes.Equal(pub.Ed25519, v.SigPub.Ed25519) {
			t.Errorf("%s: public key differs", v.Name)
		}
		if id, err := v.SigPub.SigKeyID(); err != nil || id != v.SigKeyID {
			t.Errorf("%s: sig_key_id %s (%v), want %s", v.Name, id, err, v.SigKeyID)
		}
	}
}

func TestVectorEncKeyID(t *testing.T) {
	for _, v := range load[encKeyIDVector](t, "enc_key_id.json") {
		sk, err := recoverykey.FromSeed(v.Seed)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(sk.Public().Bytes(), v.EncPub) {
			t.Errorf("%s: public key differs", v.Name)
		}
		if id, err := EncKeyID(v.EncPub); err != nil || id != v.EncKeyID {
			t.Errorf("%s: enc_key_id %s (%v), want %s", v.Name, id, err, v.EncKeyID)
		}
	}
}

func TestVectorDigest(t *testing.T) {
	for _, v := range load[digestVector](t, "digest.json") {
		canon, err := canonical.Canonicalize(v.Object)
		if err != nil {
			t.Fatal(err)
		}
		d, err := DigestCanonical(v.Type, canon)
		if err != nil {
			t.Fatal(err)
		}
		if d.Hex() != v.Digest {
			t.Errorf("%s: digest %s, want %s", v.Name, d.Hex(), v.Digest)
		}
		var obj struct {
			Signatures []struct {
				Sig HybridSig `json:"sig"`
			} `json:"signatures"`
		}
		if err := json.Unmarshal(v.Object, &obj); err != nil || len(obj.Signatures) != 1 {
			t.Fatalf("%s: %v", v.Name, err)
		}
		check(t, v.Name, v.Verdict, v.SigPub.Verify(d, obj.Signatures[0].Sig))
	}
}

func TestVectorHybridSig(t *testing.T) {
	for _, v := range load[hybridSigVector](t, "hybrid_sig.json") {
		var d Digest
		b, _ := hex.DecodeString(string(v.Digest))
		copy(d[:], b)
		check(t, v.Name, v.Verdict, v.SigPub.Verify(d, v.Sig))
	}
}

func TestVectorAAD(t *testing.T) {
	for _, v := range load[aadVector](t, "aad_payload.json") {
		a, err := payloadFields(v.Fields).Bytes()
		check(t, v.Name, v.Verdict, err)
		if err == nil && hex.EncodeToString(a) != v.AADHex {
			t.Errorf("%s: aad %x, want %s", v.Name, a, v.AADHex)
		}
	}
	for _, v := range load[aadVector](t, "aad_recipient.json") {
		a, err := recipientFields(v.Fields).Bytes()
		check(t, v.Name, v.Verdict, err)
		if err == nil && hex.EncodeToString(a) != v.AADHex {
			t.Errorf("%s: aad %x, want %s", v.Name, a, v.AADHex)
		}
	}
	for _, v := range load[aadBoundaryVector](t, "aad_boundary.json") {
		enc := func(d string, fs []string) string {
			var bs [][]byte
			for _, f := range fs {
				bs = append(bs, []byte(f))
			}
			a, err := AAD(d, bs...)
			if err != nil {
				t.Fatal(err)
			}
			return hex.EncodeToString(a)
		}
		a, b := enc(v.DomainA, v.FieldsA), enc(v.DomainB, v.FieldsB)
		if a != v.AADA || b != v.AADB || a == b {
			t.Errorf("%s: framing %s / %s", v.Name, a, b)
		}
	}
}

func TestVectorDEKWrap(t *testing.T) {
	for _, v := range load[dekWrapVector](t, "dek_wrap.json") {
		sk, err := recoverykey.FromSeed(v.RecipientSeed)
		if err != nil {
			t.Fatal(err)
		}
		dek, err := UnwrapDEK(sk, recipientFields(v.OpenFields), v.Enc, v.WrappedDEK)
		check(t, v.Name, v.Verdict, err)
		if err == nil && !bytes.Equal(dek, v.DEK) {
			t.Errorf("%s: dek differs", v.Name)
		}
	}
}

func TestVectorPayload(t *testing.T) {
	for _, v := range load[payloadVector](t, "payload.json") {
		pt, err := OpenPayload(v.DEK, v.Nonce, payloadFields(v.OpenFields), v.Ciphertext)
		check(t, v.Name, v.Verdict, err)
		if err == nil && string(pt) != v.Plaintext {
			t.Errorf("%s: plaintext differs", v.Name)
		}
	}
}

func TestVectorOpID(t *testing.T) {
	for _, v := range load[opIDVector](t, "opid.json") {
		var got UUID
		var err error
		c := func(s string) Counter {
			n, e := ParseCounter(s)
			if e != nil {
				t.Fatal(e)
			}
			return n
		}
		switch v.Kind {
		case "rotation":
			got, err = RotationOpID(UUID(v.Inputs[0]), c(v.Inputs[1]), c(v.Inputs[2]), c(v.Inputs[3]))
		case "request":
			got, err = RequestOpID(UUID(v.Inputs[0]), c(v.Inputs[1]))
		}
		if err != nil || string(got) != v.OpID {
			t.Errorf("%s: %s (%v), want %s", v.Name, got, err, v.OpID)
		}
	}
}
