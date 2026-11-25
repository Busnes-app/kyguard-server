package pqcrypto

// Golden vector generation (§3.8). `go generate ./internal/pqcrypto` rewrites
// testdata/vectors; TestVectorsCurrent fails when the committed files differ from what the
// generator produces. Expected verdicts are stated by the generator, never computed by the
// code under test; vectors_test.go consumes the files independently.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"testing/cryptotest"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

//go:generate go test -run ^TestVectorsCurrent$ . -update

var update = flag.Bool("update", false, "rewrite testdata/vectors")

const vectorDir = "testdata/vectors"

// seed derives a fixed 32-byte seed from a label.
func seed(label string) []byte {
	s := sha256.Sum256([]byte("kyguard-vector/" + label))
	return s[:]
}

func mustSigningKey(t testing.TB, label string) *SigningKey {
	t.Helper()
	k, err := NewSigningKey(seed(label+"/mldsa"), seed(label+"/ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustXWing(t testing.TB, label string) recoverykey.PrivateKey {
	t.Helper()
	k, err := recoverykey.FromSeed(seed(label + "/xwing"))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// generators maps each vector file to its generator. Each runs under its own fixed
// global random seed so one file's change never shifts another's bytes.
var generators = map[string]func(t *testing.T) any{
	"canonical.json":     genCanonical,
	"counter.json":       genCounter,
	"base64url.json":     genBase64,
	"sig_key_id.json":    genSigKeyID,
	"enc_key_id.json":    genEncKeyID,
	"digest.json":        genDigest,
	"hybrid_sig.json":    genHybridSig,
	"aad_payload.json":   genAADPayload,
	"aad_recipient.json": genAADRecipient,
	"aad_boundary.json":  genAADBoundary,
	"dek_wrap.json":      genDEKWrap,
	"payload.json":       genPayload,
	"opid.json":          genOpID,
}

func renderVectors(t *testing.T) map[string][]byte {
	out := map[string][]byte{}
	for name, gen := range generators {
		s := sha256.Sum256([]byte(name))
		cryptotest.SetGlobalRandom(t, uint64(s[0])<<8|uint64(s[1]))
		b, err := json.MarshalIndent(gen(t), "", "  ")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out[name] = append(b, '\n')
	}
	return out
}

func TestVectorsCurrent(t *testing.T) {
	files := renderVectors(t)
	if *update {
		if err := os.MkdirAll(vectorDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			if err := os.WriteFile(filepath.Join(vectorDir, name), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(vectorDir, name))
		if err != nil {
			t.Fatalf("%s: %v (run go generate ./internal/pqcrypto)", name, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s is stale: run go generate ./internal/pqcrypto", name)
		}
	}
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if _, ok := files[e.Name()]; !ok {
			t.Errorf("%s has no generator", e.Name())
		}
	}
}

// ok is the verdict of a vector that must be accepted.
const ok = "ok"

type canonicalVector struct {
	Name      string `json:"name"`
	InputB64  string `json:"input_b64"`
	Canonical string `json:"canonical,omitempty"`
	Verdict   string `json:"verdict"`
}

func genCanonical(*testing.T) any {
	v := func(name, in, canon, verdict string) canonicalVector {
		return canonicalVector{name, EncodeB64([]byte(in)), canon, verdict}
	}
	return []canonicalVector{
		v("key order by UTF-16 code units", `{"b":1,"a":2,"\u20ac":3,"\ud83d\ude00":4,"\ufb33":5}`, "{\"a\":2,\"b\":1,\"\u20ac\":3,\"\U0001F600\":4,\"\uFB33\":5}", ok),
		v("whitespace and escapes normalized", " { \"s\" : \"\\u0041\\/\\u001f\\u007f<>&\\n\" , \"t\":[ true,false,null ] } ", `{"s":"A/\u001f`+"\x7f"+`<>&\n","t":[true,false,null]}`, ok),
		v("nested objects sorted", `{"z":{"y":1,"x":[{"b":0,"a":-9007199254740991}]}}`, `{"z":{"x":[{"a":-9007199254740991,"b":0}],"y":1}}`, ok),
		v("duplicate key", `{"a":1,"a":2}`, "", "duplicate_key"),
		v("duplicate key nested", `{"o":{"k":"x","k":"x"}}`, "", "duplicate_key"),
		v("duplicate key via escape", `{"a":1,"a":2}`, "", "duplicate_key"),
		v("malformed UTF-8 byte", "{\"a\":\"\xff\"}", "", "invalid_utf8"),
		v("overlong UTF-8", "{\"a\":\"\xc0\xaf\"}", "", "invalid_utf8"),
		v("UTF-8 encoded surrogate", "{\"a\":\"\xed\xa0\x80\"}", "", "invalid_utf8"),
		v("lone high surrogate escape", `{"a":"\ud800"}`, "", "invalid_utf8"),
		v("lone low surrogate escape", `{"a":"\udc00x"}`, "", "invalid_utf8"),
		v("high surrogate then non-surrogate escape", `{"a":"\ud800\u0041"}`, "", "invalid_utf8"),
		v("two low surrogate escapes", `{"a":"\udc00\udc00"}`, "", "invalid_utf8"),
		v("fraction rejected", `{"a":1.0}`, "", "number_out_of_profile"),
		v("exponent rejected", `{"a":1e2}`, "", "number_out_of_profile"),
		v("integer above 2^53-1", `{"a":9007199254740992}`, "", "number_out_of_profile"),
		v("negative zero", `{"a":-0}`, "", "number_out_of_profile"),
		v("leading zero number", `{"a":01}`, "", "syntax"),
		v("trailing data", `{"a":1} {}`, "", "syntax"),
		v("trailing comma", `{"a":1,}`, "", "syntax"),
		v("raw control character", "{\"a\":\"\x01\"}", "", "syntax"),
	}
}

type counterVector struct {
	Name    string `json:"name"`
	JSON    string `json:"json"`
	Value   string `json:"value,omitempty"`
	Verdict string `json:"verdict"`
}

func genCounter(*testing.T) any {
	return []counterVector{
		{"zero", `"0"`, "0", ok},
		{"one", `"1"`, "1", ok},
		{"max 2^63-1", `"9223372036854775807"`, "9223372036854775807", ok},
		{"above 2^63-1", `"9223372036854775808"`, "", "invalid_counter"},
		{"2^64", `"18446744073709551616"`, "", "invalid_counter"},
		{"leading zero", `"01"`, "", "invalid_counter"},
		{"double zero", `"00"`, "", "invalid_counter"},
		{"plus sign", `"+1"`, "", "invalid_counter"},
		{"minus sign", `"-1"`, "", "invalid_counter"},
		{"empty", `""`, "", "invalid_counter"},
		{"whitespace", `" 1"`, "", "invalid_counter"},
		{"JSON number", `1`, "", "invalid_counter"},
		{"non-ASCII digit", `"١"`, "", "invalid_counter"},
	}
}

type base64Vector struct {
	Name    string `json:"name"`
	Input   string `json:"input"`
	BytesHx string `json:"bytes_hex,omitempty"`
	Verdict string `json:"verdict"`
}

func genBase64(*testing.T) any {
	return []base64Vector{
		{"empty", "", "", ok},
		{"two bytes", "_-8", "ffef", ok},
		{"three bytes", "AQID", "010203", ok},
		{"padding", "AQI=", "", "invalid_base64url"},
		{"standard alphabet", "+/8", "", "invalid_base64url"},
		{"non-zero trailing bits", "AQJ", "", "invalid_base64url"},
		{"embedded newline", "AQ\nID", "", "invalid_base64url"},
		{"embedded carriage return", "AQ\rID", "", "invalid_base64url"},
	}
}

type sigKeyIDVector struct {
	Name        string    `json:"name"`
	MLDSASeed   B64       `json:"mldsa65_seed"`
	Ed25519Seed B64       `json:"ed25519_seed"`
	SigPub      HybridPub `json:"sig_pub"`
	SigKeyID    HexID     `json:"sig_key_id"`
}

func genSigKeyID(t *testing.T) any {
	var out []sigKeyIDVector
	for _, l := range []string{"custodian-a", "user-a"} {
		k := mustSigningKey(t, l)
		pub := k.Public()
		h := sha256.New()
		h.Write([]byte("kyguard/1/sigkey"))
		h.Write([]byte{0})
		h.Write(pub.MLDSA65)
		h.Write(pub.Ed25519)
		out = append(out, sigKeyIDVector{l, seed(l + "/mldsa"), seed(l + "/ed25519"), pub, HexID(hex.EncodeToString(h.Sum(nil)))})
	}
	return out
}

type encKeyIDVector struct {
	Name     string `json:"name"`
	Seed     B64    `json:"xwing_seed"`
	EncPub   B64    `json:"enc_pub"`
	EncKeyID HexID  `json:"enc_key_id"`
}

func genEncKeyID(t *testing.T) any {
	var out []encKeyIDVector
	for _, l := range []string{"broker-a", "recovery"} {
		pub := mustXWing(t, l).Public().Bytes()
		s := sha256.Sum256(pub)
		out = append(out, encKeyIDVector{l, seed(l + "/xwing"), pub, HexID(hex.EncodeToString(s[:]))})
	}
	return out
}

type digestVector struct {
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Object    json.RawMessage `json:"object"`
	Canonical string          `json:"canonical"`
	Digest    HexID           `json:"digest"`
	SigPub    HybridPub       `json:"sig_pub"`
	Verdict   string          `json:"verdict"`
}

// domainHash is the generator's own D, written out from §3.1 rule 4.
func domainHash(domain string, canon []byte) Digest {
	return sha256.Sum256(append(append([]byte(domain), 0), canon...))
}

func genDigest(t *testing.T) any {
	k := mustSigningKey(t, "custodian-a")
	kid, _ := k.Public().SigKeyID()
	body := `{"type":"policy","epoch":"3","note":"€ <&>","approvals":[]}`
	canonBody := `{"epoch":"3","note":"€ <&>","type":"policy"}` // signatures and approvals removed
	signed := func(name, typ string, signedOver []byte, verdict string) digestVector {
		d := domainHash("kyguard/1/"+typ, []byte(canonBody))
		sig, err := k.Sign(sha256.Sum256(signedOver))
		if err != nil {
			t.Fatal(err)
		}
		sigJSON, _ := json.Marshal([]map[string]any{{"signer_role": "custodian", "sig_key_id": kid, "sig": sig}})
		obj := body[:len(body)-1] + `,"signatures":` + string(sigJSON) + `}`
		return digestVector{name, typ, json.RawMessage(obj), canonBody, d.Hex(), k.Public(), verdict}
	}
	good := append(append([]byte("kyguard/1/policy"), 0), canonBody...)
	wrongDomain := append(append([]byte("kyguard/1/pool"), 0), canonBody...)
	full := append(append([]byte("kyguard/1/policy"), 0), `{"approvals":[],"epoch":"3","note":"€ <&>","type":"policy"}`...)
	return []digestVector{
		signed("signature over D", "policy", good, ok),
		signed("wrong domain type", "policy", wrongDomain, "invalid_signature"),
		signed("digest covered approvals", "policy", full, "invalid_signature"),
	}
}

type hybridSigVector struct {
	Name    string    `json:"name"`
	SigPub  HybridPub `json:"sig_pub"`
	Digest  HexID     `json:"digest"`
	Sig     HybridSig `json:"sig"`
	Verdict string    `json:"verdict"`
}

func genHybridSig(t *testing.T) any {
	k := mustSigningKey(t, "custodian-a")
	other := mustSigningKey(t, "custodian-b")
	d := sha256.Sum256([]byte("kyguard hybrid signature vector"))
	sig, err := k.Sign(d)
	if err != nil {
		t.Fatal(err)
	}
	osig, err := other.Sign(d)
	if err != nil {
		t.Fatal(err)
	}
	flip := func(b B64) B64 { c := append(B64(nil), b...); c[len(c)/2] ^= 1; return c }
	v := func(name string, s HybridSig, verdict string) hybridSigVector {
		return hybridSigVector{name, k.Public(), Digest(d).Hex(), s, verdict}
	}
	return []hybridSigVector{
		v("both halves valid", sig, ok),
		v("ML-DSA half invalid", HybridSig{HybridAlg, flip(sig.MLDSA65), sig.Ed25519}, "invalid_signature"),
		v("Ed25519 half invalid", HybridSig{HybridAlg, sig.MLDSA65, flip(sig.Ed25519)}, "invalid_signature"),
		v("ML-DSA half from another key", HybridSig{HybridAlg, osig.MLDSA65, sig.Ed25519}, "invalid_signature"),
		v("Ed25519 half from another key", HybridSig{HybridAlg, sig.MLDSA65, osig.Ed25519}, "invalid_signature"),
		v("ML-DSA half missing", HybridSig{HybridAlg, nil, sig.Ed25519}, "invalid_signature"),
		v("Ed25519 half missing", HybridSig{HybridAlg, sig.MLDSA65, nil}, "invalid_signature"),
		v("wrong alg", HybridSig{"ed25519", sig.MLDSA65, sig.Ed25519}, "invalid_signature_alg"),
	}
}

type aadVector struct {
	Name    string            `json:"name"`
	Fields  map[string]string `json:"fields"`
	AADHex  string            `json:"aad_hex,omitempty"`
	Verdict string            `json:"verdict"`
}

// frame is the generator's own AAD framing, written out from §3.1 rule 9.
func frame(domain string, fs ...[]byte) string {
	b := append([]byte(domain), 0)
	for _, f := range fs {
		b = append(b, byte(len(f)>>24), byte(len(f)>>16), byte(len(f)>>8), byte(len(f)))
		b = append(b, f...)
	}
	return hex.EncodeToString(b)
}

func be64(n uint64) []byte {
	return []byte{byte(n >> 56), byte(n >> 48), byte(n >> 40), byte(n >> 32), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

const (
	vEnvelope = "0190b2a4-5c6d-7e8f-9a0b-1c2d3e4f5a6b"
	vAccount  = "0190b2a4-0000-7000-8000-00000000a001"
	vBroker   = "4c2f0e1a-9b8d-4c6e-a7f3-2d1b0c9e8f7a"
)

func genAADPayload(*testing.T) any {
	pd := Digest(sha256.Sum256([]byte("policy"))).Hex()
	f := map[string]string{"envelope_kind": "managed", "envelope_id": vEnvelope, "account_id": vAccount,
		"secret_version": "7", "epoch": "3", "policy_digest": string(pd), "recovery_epoch": "1"}
	good := frame(DomainPayload, []byte("managed"), []byte(vEnvelope), []byte(vAccount), be64(7), be64(3), []byte(pd), be64(1))
	bad := func(k, val string) map[string]string {
		c := map[string]string{}
		for a, b := range f {
			c[a] = b
		}
		c[k] = val
		return c
	}
	return []aadVector{
		{"managed payload", f, good, ok},
		{"max counters", bad("secret_version", "9223372036854775807"), frame(DomainPayload, []byte("managed"), []byte(vEnvelope), []byte(vAccount), be64(1<<63-1), be64(3), []byte(pd), be64(1)), ok},
		{"unknown envelope kind", bad("envelope_kind", "managedx"), "", "invalid_aad"},
		{"uppercase UUID", bad("account_id", "0190B2A4-0000-7000-8000-00000000A001"), "", "invalid_aad"},
		{"non-hex policy digest", bad("policy_digest", "zz"), "", "invalid_aad"},
	}
}

func genAADRecipient(t *testing.T) any {
	kid := HexID(mustXWing(t, "broker-a").Public().ID())
	rid := HexID(mustXWing(t, "recovery").Public().ID())
	f := func(kind, rtype, rcpt string, key HexID) map[string]string {
		return map[string]string{"envelope_kind": kind, "envelope_id": vEnvelope, "account_id": vAccount,
			"secret_version": "7", "recipient_id": rcpt, "recipient_type": rtype, "key_id": string(key)}
	}
	enc := func(kind, rtype, rcpt string, key HexID) string {
		return frame(DomainRecipient, []byte(kind), []byte(vEnvelope), []byte(vAccount), be64(7), []byte(rcpt), []byte(rtype), []byte(key))
	}
	return []aadVector{
		{"broker recipient", f("managed", "broker", vBroker, kid), enc("managed", "broker", vBroker, kid), ok},
		{"recovery recipient", f("managed", "recovery", string(rid), rid), enc("managed", "recovery", string(rid), rid), ok},
		{"unknown recipient type", f("managed", "custodian", vBroker, kid), "", "invalid_aad"},
		{"broker with hex id", f("managed", "broker", string(rid), kid), "", "invalid_aad"},
		{"recovery with uuid id", f("managed", "recovery", vBroker, rid), "", "invalid_aad"},
	}
}

type dekWrapVector struct {
	Name          string            `json:"name"`
	RecipientSeed B64               `json:"recipient_xwing_seed"`
	SealFields    map[string]string `json:"seal_fields"`
	OpenFields    map[string]string `json:"open_fields"`
	DEK           B64               `json:"dek"`
	Enc           B64               `json:"enc"`
	WrappedDEK    B64               `json:"wrapped_dek"`
	Verdict       string            `json:"verdict"`
}

func recipientFields(m map[string]string) RecipientAADFields {
	sv, _ := ParseCounter(m["secret_version"])
	return RecipientAADFields{m["envelope_kind"], UUID(m["envelope_id"]), UUID(m["account_id"]), sv,
		m["recipient_id"], m["recipient_type"], HexID(m["key_id"])}
}

func genDEKWrap(t *testing.T) any {
	sk := mustXWing(t, "broker-a")
	kid := sk.Public().ID()
	dek := seed("dek")
	base := map[string]string{"envelope_kind": "managed", "envelope_id": vEnvelope, "account_id": vAccount,
		"secret_version": "7", "recipient_id": vBroker, "recipient_type": "broker", "key_id": kid}
	with := func(k, v string) map[string]string {
		c := map[string]string{}
		for a, b := range base {
			c[a] = b
		}
		c[k] = v
		return c
	}
	enc, wrapped, err := WrapDEK(sk.Public().Bytes(), recipientFields(base), dek)
	if err != nil {
		t.Fatal(err)
	}
	v := func(name string, open map[string]string, w B64, verdict string) dekWrapVector {
		return dekWrapVector{name, seed("broker-a/xwing"), base, open, dek, enc, w, verdict}
	}
	tampered := append(B64(nil), wrapped...)
	tampered[0] ^= 1
	return []dekWrapVector{
		v("broker wrap", base, wrapped, ok),
		v("opened as user recipient", with("recipient_type", "user"), wrapped, "decrypt_failed"),
		v("opened for another secret_version", with("secret_version", "8"), wrapped, "decrypt_failed"),
		v("opened as vaulted", with("envelope_kind", "vaulted"), wrapped, "decrypt_failed"),
		v("tampered wrapped_dek", base, tampered, "decrypt_failed"),
	}
}

type payloadVector struct {
	Name       string            `json:"name"`
	DEK        B64               `json:"dek"`
	Nonce      B64               `json:"nonce"`
	SealFields map[string]string `json:"seal_fields"`
	OpenFields map[string]string `json:"open_fields"`
	Plaintext  string            `json:"plaintext"`
	Ciphertext B64               `json:"ciphertext"`
	Verdict    string            `json:"verdict"`
}

func payloadFields(m map[string]string) PayloadAADFields {
	c := func(k string) Counter { n, _ := ParseCounter(m[k]); return n }
	return PayloadAADFields{m["envelope_kind"], UUID(m["envelope_id"]), UUID(m["account_id"]),
		c("secret_version"), c("epoch"), HexID(m["policy_digest"]), c("recovery_epoch")}
}

func genPayload(t *testing.T) any {
	dek, nonce := seed("dek"), seed("nonce")[:NonceBytes]
	pd := string(Digest(sha256.Sum256([]byte("policy"))).Hex())
	base := map[string]string{"envelope_kind": "managed", "envelope_id": vEnvelope, "account_id": vAccount,
		"secret_version": "7", "epoch": "3", "policy_digest": pd, "recovery_epoch": "1"}
	with := func(k, v string) map[string]string {
		c := map[string]string{}
		for a, b := range base {
			c[a] = b
		}
		c[k] = v
		return c
	}
	pt := `{"password":"S3cret-pass_word.!@"}`
	ct, err := SealPayload(dek, nonce, payloadFields(base), []byte(pt))
	if err != nil {
		t.Fatal(err)
	}
	v := func(name string, open map[string]string, verdict string) payloadVector {
		return payloadVector{name, dek, nonce, base, open, pt, ct, verdict}
	}
	return []payloadVector{
		v("payload", base, ok),
		v("recovery_epoch differs", with("recovery_epoch", "0"), "decrypt_failed"),
		v("policy epoch differs", with("epoch", "4"), "decrypt_failed"),
		v("policy digest differs", with("policy_digest", string(Digest(sha256.Sum256([]byte("other"))).Hex())), "decrypt_failed"),
	}
}

type opIDVector struct {
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Inputs []string `json:"inputs"`
	OpID   string   `json:"opid"`
}

func genOpID(*testing.T) any {
	uuidOf := func(h string) string {
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	}
	op := func(fs ...[]byte) string {
		b, _ := hex.DecodeString(frame(DomainOperation, fs...))
		s := sha256.Sum256(b)
		return uuidOf(hex.EncodeToString(s[:16]))
	}
	const req = "0190b2a4-0000-7000-8000-0000000000f1"
	return []opIDVector{
		{"rotation attempt 0", "rotation", []string{vAccount, "3", "12", "0"}, op([]byte(vAccount), be64(3), be64(12), be64(0))},
		{"rotation attempt 1", "rotation", []string{vAccount, "3", "12", "1"}, op([]byte(vAccount), be64(3), be64(12), be64(1))},
		{"request attempt 0", "request", []string{req, "0"}, op([]byte(req), be64(0))},
	}
}

type aadBoundaryVector struct {
	Name    string   `json:"name"`
	DomainA string   `json:"domain_a"`
	FieldsA []string `json:"fields_a"` // UTF-8 field values
	AADA    string   `json:"aad_a_hex"`
	DomainB string   `json:"domain_b"`
	FieldsB []string `json:"fields_b"`
	AADB    string   `json:"aad_b_hex"`
}

// genAADBoundary pairs inputs whose plain concatenation collides; framed, they must not.
func genAADBoundary(*testing.T) any {
	v := func(name, da string, fa []string, db string, fb []string) aadBoundaryVector {
		bs := func(ss []string) [][]byte {
			var out [][]byte
			for _, s := range ss {
				out = append(out, []byte(s))
			}
			return out
		}
		return aadBoundaryVector{name, da, fa, frame(da, bs(fa)...), db, fb, frame(db, bs(fb)...)}
	}
	return []aadBoundaryVector{
		v("byte moved across a field boundary", DomainRecipient, []string{"managed", "ab", "c"}, DomainRecipient, []string{"managed", "a", "bc"}),
		v("field split in two", DomainPayload, []string{"vaultedmanaged"}, DomainPayload, []string{"vaulted", "managed"}),
		v("empty field added", DomainPayload, []string{"x"}, DomainPayload, []string{"x", ""}),
		v("domain absorbs a field byte", "kyguard/1/payloa", []string{"dx"}, DomainPayload, []string{"x"}),
	}
}
