package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

const pass = "correct horse battery staple"

type fakePrompt struct {
	pass    string
	confirm bool
}

func (f *fakePrompt) Passphrase(string, bool) (string, error) { return f.pass, nil }
func (f *fakePrompt) Confirm(string) (bool, error)            { return f.confirm, nil }

type fakeClient struct {
	drafts    map[string]*Draft
	submitted map[string][]byte
}

func (c *fakeClient) Bundle(context.Context) ([]byte, error)             { return nil, errors.New("unused") }
func (c *fakeClient) Manifests(context.Context) ([][]byte, error)        { return nil, errors.New("unused") }
func (c *fakeClient) Draft(_ context.Context, id string) (*Draft, error) { return c.drafts[id], nil }
func (c *fakeClient) SubmitDraft(context.Context, []byte) (string, error) {
	return "", errors.New("unused")
}
func (c *fakeClient) SubmitSignature(_ context.Context, id string, b []byte) error {
	c.submitted[id] = b
	return nil
}

// cheap is the lowest cost password.Params accepts, to keep tests fast.
var cheap = password.Params{Memory: 8 * 1024, Time: 1, Threads: 1}

type env struct {
	t      *testing.T
	dir    string
	app    *App
	out    *bytes.Buffer
	prompt *fakePrompt
	fp     string
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	e := &env{t: t, dir: dir, out: &bytes.Buffer{}, prompt: &fakePrompt{pass: pass, confirm: true}}
	e.app = &App{Home: filepath.Join(dir, "home"), Out: e.out, Prompt: e.prompt, KDF: cheap}
	return e
}

func (e *env) run(args ...string) error {
	e.t.Helper()
	e.out.Reset()
	return e.app.Run(context.Background(), args)
}

func (e *env) must(args ...string) string {
	e.t.Helper()
	if err := e.run(args...); err != nil {
		e.t.Fatalf("%v: %v", args, err)
	}
	return e.out.String()
}

func (e *env) path(name string) string { return filepath.Join(e.dir, name) }

var fpRE = regexp.MustCompile(`bootstrap_fingerprint  ([0-9a-f]{64})`)

// ceremony runs init into dir/ceremony and returns the fingerprint.
func (e *env) ceremony(sub string, n, m string) string {
	e.t.Helper()
	rk, err := recoverykey.Generate()
	if err != nil {
		e.t.Fatal(err)
	}
	pub := e.path(sub + ".pub")
	if err := os.WriteFile(pub, []byte(hex.EncodeToString(rk.Public().Bytes())+"\n"), 0o644); err != nil {
		e.t.Fatal(err)
	}
	out := e.must("init", "--recovery-pub", pub, "--recovery-threshold", "2", "--recovery-shares", "3",
		"--custodians", n, "--threshold", m, "--out", e.path(sub))
	f := fpRE.FindStringSubmatch(out)
	if f == nil {
		e.t.Fatalf("no fingerprint in %s", out)
	}
	return f[1]
}

func (e *env) pinned() *pqcrypto.Trust {
	e.t.Helper()
	tr, err := e.app.loadTrust()
	if err != nil {
		e.t.Fatal(err)
	}
	return tr
}

func (e *env) write(name string, v any) string {
	e.t.Helper()
	b, err := canonical.Marshal(v)
	if err != nil {
		e.t.Fatal(err)
	}
	p := e.path(name)
	if err := os.WriteFile(p, b, 0o644); err != nil {
		e.t.Fatal(err)
	}
	return p
}

// signBy has custodians sign a draft file in turn and returns the final file.
func (e *env) signBy(draft string, extra []string, custodians ...int) string {
	e.t.Helper()
	cur := draft
	for _, c := range custodians {
		next := cur + "." + string(rune('0'+c))
		args := append([]string{"sign", "--key", e.path("ceremony/custodian-" + string(rune('0'+c)) + ".key"), "--draft", cur, "--out", next}, extra...)
		e.must(args...)
		cur = next
	}
	return cur
}

func vaultedPolicy(tr *pqcrypto.Trust, account pqcrypto.UUID, epoch pqcrypto.Counter, users ...pqcrypto.UUID) *pqcrypto.PolicyManifest {
	if users == nil {
		users = []pqcrypto.UUID{}
	}
	return &pqcrypto.PolicyManifest{
		Header: pqcrypto.Header{Type: pqcrypto.TypePolicy, DeploymentID: tr.DeploymentID(), Epoch: epoch,
			Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: account}, SignerRole: pqcrypto.RoleCustodian},
		AccountID: account, AccountKind: pqcrypto.KindVaulted, AllowedUserPrincipalIDs: users,
		AllowedApproverPrincipalIDs: []pqcrypto.UUID{}, RecoveryEscrowEnabled: false,
	}
}

const (
	alice   = pqcrypto.UUID("0190b2a4-6666-7666-8666-000000000001")
	account = pqcrypto.UUID("0190b2a4-3333-7333-8333-000000000001")
)

func TestNoPinRefusesEverything(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	for _, args := range [][]string{
		{"import", e.path("ceremony/bundle.json")},
		{"enroll", "--principal-id", string(alice), "--issuer", "https://idp", "--subject", "alice", "--key-out", e.path("a.key"), "--draft-out", e.path("a.json")},
		{"sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.path("ceremony/bundle.json"), "--out", e.path("x")},
	} {
		if err := e.run(args...); !errors.Is(err, ErrNotPinned) {
			t.Errorf("%s without a pin: err %v, want ErrNotPinned", args[0], err)
		}
	}
	// A different fingerprint pins nothing.
	other := newEnv(t).ceremony("ceremony", "1", "1")
	if err := e.run("trust", other, "--bundle", e.path("ceremony/bundle.json")); !errors.Is(err, pqcrypto.ErrFingerprint) {
		t.Fatalf("trust with another fingerprint: err %v, want ErrFingerprint", err)
	}
	if err := e.run("import", e.path("ceremony/bundle.json")); !errors.Is(err, ErrNotPinned) {
		t.Fatalf("after a failed trust: err %v, want ErrNotPinned", err)
	}
	if _, err := os.Stat(filepath.Join(e.app.Home, stateFile)); !os.IsNotExist(err) {
		t.Fatalf("a failed trust left state behind: %v", err)
	}
	out := e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	if !strings.Contains(out, "custodians 2 of 3") {
		t.Fatalf("trust output: %s", out)
	}
	if err := e.run("trust", other, "--bundle", e.path("ceremony/bundle.json")); err == nil || !strings.Contains(err.Error(), "already pinned") {
		t.Fatalf("re-pin without --replace: err %v", err)
	}
}

func TestInitWarnsOneOfOne(t *testing.T) {
	e := newEnv(t)
	e.ceremony("ceremony", "1", "1")
	if !strings.Contains(e.out.String(), "WARNING: a 1-of-1") {
		t.Fatalf("no 1-of-1 warning: %s", e.out)
	}
	info, err := os.Stat(e.path("ceremony/custodian-1.key"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v (%v), want 0600", info.Mode().Perm(), err)
	}
}

func TestEnrollAndSignKeyEnrollment(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	out := e.must("enroll", "--principal-id", string(alice), "--issuer", "https://idp.example.test", "--subject", "alice",
		"--key-out", e.path("alice.key"), "--draft-out", e.path("alice-draft.json"))
	for _, s := range []string{"principal_id  " + string(alice), "sig_key_id", "enc_key_id", "issuer        https://idp.example.test"} {
		if !strings.Contains(out, s) {
			t.Fatalf("enroll output lacks %q: %s", s, out)
		}
	}
	if _, err := openKeyFile(e.path("alice.key"), "wrong passphrase!", KindUser); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: err %v", err)
	}
	k, err := openKeyFile(e.path("alice.key"), pass, KindUser)
	if err != nil || k.Enc.IsZero() {
		t.Fatalf("open user key: %v", err)
	}
	signed := e.signBy(e.path("alice-draft.json"), nil, 1)
	if !strings.Contains(e.out.String(), "not yet complete") {
		t.Fatalf("one custodian completed a 2-of-3 manifest: %s", e.out)
	}
	e.signBy(signed, nil, 2)
	if !strings.Contains(e.out.String(), "complete: accepted key_enrollment epoch 1") {
		t.Fatalf("second signature: %s", e.out)
	}
	if e.pinned().Enrollment(alice) == nil {
		t.Fatal("accepted enrollment was not persisted")
	}
}

func TestSignRefusesRollbackForkAndOutsiders(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	tr := e.pinned()
	ep1 := e.signBy(e.write("p1.json", vaultedPolicy(tr, account, 1, alice)), nil, 1, 3)
	ep2 := e.signBy(e.write("p2.json", vaultedPolicy(tr, account, 2, alice)), nil, 2, 3)
	if r := e.pinned().Lookup(pqcrypto.TypePolicy, account); r == nil || r.Epoch != 2 {
		t.Fatalf("high-water mark %+v, want epoch 2", r)
	}
	// A fresh CLI sees epoch 2 first, then refuses epoch 1 and a fork of epoch 2.
	f := newEnv(t)
	f.dir = e.dir
	f.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	f.must("import", ep2)
	if err := f.run("import", ep1); !errors.Is(err, pqcrypto.ErrRollback) {
		t.Fatalf("import lower epoch: err %v, want ErrRollback", err)
	}
	// The fork is signed on a CLI that has not seen epoch 2; e itself refuses to sign it.
	if err := e.run("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.write("p2x.json", vaultedPolicy(tr, account, 2)), "--out", e.path("ox")); !errors.Is(err, pqcrypto.ErrEquivocation) {
		t.Fatalf("sign a fork of a verified epoch: err %v, want ErrEquivocation", err)
	}
	h := newEnv(t)
	h.dir = e.dir
	h.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	fork := h.signBy(e.write("p2b.json", vaultedPolicy(tr, account, 2)), nil, 1, 2)
	if err := f.run("import", fork); !errors.Is(err, pqcrypto.ErrEquivocation) || !strings.Contains(err.Error(), "ALERT") {
		t.Fatalf("import same-epoch fork: err %v, want an ErrEquivocation alert", err)
	}
	if err := f.run("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.write("p1again.json", vaultedPolicy(tr, account, 1, alice)), "--out", e.path("o1")); !errors.Is(err, pqcrypto.ErrRollback) {
		t.Fatalf("sign lower epoch: err %v, want ErrRollback", err)
	}
	if err := f.run("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.write("p2c.json", vaultedPolicy(tr, account, 2)), "--out", e.path("o2")); !errors.Is(err, pqcrypto.ErrEquivocation) {
		t.Fatalf("sign same-epoch fork: err %v, want ErrEquivocation", err)
	}
	// A custodian of another deployment cannot sign here.
	g := newEnv(t)
	g.ceremony("ceremony", "1", "1")
	if err := f.run("sign", "--key", g.path("ceremony/custodian-1.key"), "--draft", e.write("p3.json", vaultedPolicy(tr, account, 3, alice)), "--out", e.path("o3")); !errors.Is(err, pqcrypto.ErrUnknownKey) {
		t.Fatalf("outsider key: err %v, want ErrUnknownKey", err)
	}
	// Declining the confirmation signs nothing.
	f.prompt.confirm = false
	if err := f.run("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.write("p4.json", vaultedPolicy(tr, account, 4, alice)), "--out", e.path("o4")); err == nil {
		t.Fatal("signed without confirmation")
	}
	if _, err := os.Stat(e.path("o4")); !os.IsNotExist(err) {
		t.Fatal("declined signature was written")
	}
}

func TestSignManagedPolicyNeedsMatchingTarget(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	tr := e.pinned()
	td := pqcrypto.TargetDescriptor{DescriptorVersion: "1", DeploymentID: tr.DeploymentID(), AccountID: account,
		AssetID: "0190b2a4-4444-7444-8444-000000000001", ConnectorType: pqcrypto.ConnectorSSHPasswd, AuthenticatedTargetIdentity: "svc",
		Endpoint:        pqcrypto.Endpoint{Host: "db1.example.test", Port: 22, SSHHostKeySHA256: strings.Repeat("ab", 32)},
		ConnectorConfig: map[string]json.RawMessage{}, Dependencies: []json.RawMessage{}}
	target := e.write("target.json", &td)
	_, d, err := pqcrypto.DecodeTargetDescriptor(mustCanon(&td))
	if err != nil {
		t.Fatal(err)
	}
	f := false
	p := vaultedPolicy(tr, account, 1, alice)
	p.AccountKind, p.PoolID, p.TargetDescriptorDigest, p.CheckoutMode = pqcrypto.KindManaged, "0190b2a4-2222-7222-8222-000000000001", d.Hex(), pqcrypto.ModeEphemeral
	p.EnrollerPrincipalIDs, p.StandingRecipientPrincipalIDs, p.AutoStandingRelease = []pqcrypto.UUID{alice}, []pqcrypto.UUID{}, &f
	p.RotationSchedule = &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)), IntervalSeconds: 86400}
	draft := e.write("managed.json", p)
	key := e.path("ceremony/custodian-1.key")
	if err := e.run("sign", "--key", key, "--draft", draft, "--out", e.path("m1")); !errors.Is(err, ErrTargetUnverified) {
		t.Fatalf("no target: err %v, want ErrTargetUnverified", err)
	}
	td.Endpoint.Host = "attacker.example.test"
	if err := e.run("sign", "--key", key, "--draft", draft, "--target", e.write("evil.json", &td), "--out", e.path("m2")); !errors.Is(err, ErrTargetUnverified) {
		t.Fatalf("mismatched target: err %v, want ErrTargetUnverified", err)
	}
	out := e.must("sign", "--key", key, "--draft", draft, "--target", target, "--out", e.path("m3"))
	for _, s := range []string{`"db1.example.test"`, "recomputed", "NOT VERIFIED: no pool manifest", "UNKNOWN: no verified key enrollment"} {
		if !strings.Contains(out, s) {
			t.Errorf("review lacks %q:\n%s", s, out)
		}
	}
}

func TestSignShowsControlPlaneLabelsUnverified(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	c := &fakeClient{drafts: map[string]*Draft{"d1": {
		Object: mustCanon(vaultedPolicy(e.pinned(), account, 1, alice)),
		Labels: map[string]string{"account_name": "prod-db\x1b[2Kroot ok"},
	}}, submitted: map[string][]byte{}}
	e.app.Client = c
	out := e.must("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft-id", "d1")
	if !strings.Contains(out, `UNVERIFIED label from the Control Plane: "account_name" = "prod-db\x1b[2Kroot ok"`) || strings.Contains(out, "\x1b") {
		t.Fatalf("label not shown quoted and unverified:\n%q", out)
	}
	if c.submitted["d1"] == nil {
		t.Fatal("signature not submitted")
	}
}

func TestKeyFileBindsItsHeader(t *testing.T) {
	e := newEnv(t)
	e.ceremony("ceremony", "2", "1")
	p := e.path("ceremony/custodian-1.key")
	t.Chdir(e.dir)
	if _, err := openKeyFile("ceremony/custodian-1.key", pass, KindCustodian); err != nil {
		t.Fatalf("relative key path: %v", err)
	}
	if _, err := openKeyFile(p, pass, KindUser); err == nil || !strings.Contains(err.Error(), "not a user key") {
		t.Fatalf("custodian key opened as a user key: %v", err)
	}
	other, err := readKeyFile(e.path("ceremony/custodian-2.key"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	var f keyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	f.ID = other.ID // claim another custodian's identity
	b, _ := json.Marshal(f)
	q := e.path("swapped.key")
	if err := os.WriteFile(q, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openKeyFile(q, pass, KindCustodian); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("edited header: err %v, want ErrPassphrase", err)
	}
	if err := writeKeyFile(e.path("short.key"), "short", cheap, &Key{}); err == nil {
		t.Fatal("short passphrase accepted")
	}
}

func TestSignRefusesAnotherDeployment(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	p := vaultedPolicy(e.pinned(), account, 1, alice)
	p.DeploymentID = "0190b2a4-1111-7111-8111-0000000000ff"
	if err := e.run("sign", "--key", e.path("ceremony/custodian-1.key"), "--draft", e.write("dep.json", p), "--out", e.path("o")); !errors.Is(err, pqcrypto.ErrDeployment) {
		t.Fatalf("draft for another deployment: err %v, want ErrDeployment", err)
	}
}

func TestEnrollChecksDeliveryBeforeCreatingKeys(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	args := []string{"enroll", "--principal-id", string(alice), "--issuer", "https://idp", "--subject", "alice", "--key-out", e.path("a.key")}
	if err := e.run(args...); !errors.Is(err, ErrNoClient) {
		t.Fatalf("no draft destination: err %v, want ErrNoClient", err)
	}
	if err := os.WriteFile(e.path("taken.json"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.run(append(args, "--draft-out", e.path("taken.json"))...); err == nil {
		t.Fatal("existing draft file accepted")
	}
	if _, err := os.Stat(e.path("a.key")); !os.IsNotExist(err) {
		t.Fatalf("a key file was created before delivery was possible: %v", err)
	}
}

func TestSignDeliversBeforeRaisingHighWater(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	half := e.signBy(e.write("p.json", vaultedPolicy(e.pinned(), account, 1, alice)), nil, 1)
	if err := os.WriteFile(e.path("taken"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.run("sign", "--key", e.path("ceremony/custodian-2.key"), "--draft", half, "--out", e.path("taken")); err == nil {
		t.Fatal("signed into an existing file")
	}
	if e.pinned().Lookup(pqcrypto.TypePolicy, account) != nil {
		t.Fatal("an undelivered signature raised the local high-water mark")
	}
}

func TestTrustSamePinKeepsHistory(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	tr := e.pinned()
	ep1 := e.signBy(e.write("p1.json", vaultedPolicy(tr, account, 1, alice)), nil, 1, 2)
	e.signBy(e.write("p2.json", vaultedPolicy(tr, account, 2, alice)), nil, 1, 2)
	for _, extra := range [][]string{nil, {"--replace"}} {
		e.must(append([]string{"trust", fp, "--bundle", e.path("ceremony/bundle.json")}, extra...)...)
		if r := e.pinned().Lookup(pqcrypto.TypePolicy, account); r == nil || r.Epoch != 2 {
			t.Fatalf("re-pinning the same fingerprint %v dropped history: %+v", extra, r)
		}
		if err := e.run("import", ep1); !errors.Is(err, pqcrypto.ErrRollback) {
			t.Fatalf("import lower epoch after re-pin %v: err %v, want ErrRollback", extra, err)
		}
	}
}

func TestSignRefusesInvalidCoSignature(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	half := e.signBy(e.write("p.json", vaultedPolicy(e.pinned(), account, 1, alice)), nil, 1)
	var p pqcrypto.PolicyManifest
	raw, err := os.ReadFile(half)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := canonical.Decode(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.Signatures[0].Sig.MLDSA65[0] ^= 1
	bad := e.write("bad.json", &p)
	// A co-signature by a key outside the custodian set is refused the same way.
	g := newEnv(t)
	g.ceremony("ceremony", "1", "1")
	k, err := openKeyFile(g.path("ceremony/custodian-1.key"), pass, KindCustodian)
	if err != nil {
		t.Fatal(err)
	}
	q := vaultedPolicy(e.pinned(), account, 1, alice)
	if err := pqcrypto.Sign(q, pqcrypto.RoleCustodian, k.Sign); err != nil {
		t.Fatal(err)
	}
	outsider := e.write("outsider.json", q)
	// A key enrollment draft without its self-signature, with no custodian signature yet.
	e.must("enroll", "--principal-id", string(alice), "--issuer", "https://idp", "--subject", "alice",
		"--key-out", e.path("alice.key"), "--draft-out", e.path("alice.json"))
	var ke pqcrypto.KeyEnrollmentManifest
	if raw, err = os.ReadFile(e.path("alice.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := canonical.Decode(raw, &ke); err != nil {
		t.Fatal(err)
	}
	ke.Signatures = []pqcrypto.Signature{}
	unsigned := e.write("unsigned.json", &ke)
	for _, d := range []string{bad, outsider, unsigned} {
		err := e.run("sign", "--key", e.path("ceremony/custodian-2.key"), "--draft", d, "--out", d+".out")
		if err == nil || errors.Is(err, pqcrypto.ErrThreshold) {
			t.Fatalf("%s: err %v, want a refusal", filepath.Base(d), err)
		}
		if _, err := os.Stat(d + ".out"); !os.IsNotExist(err) {
			t.Fatalf("%s: a signature was released for an invalid draft", filepath.Base(d))
		}
	}
}

func TestSignCommitsBelowQuorum(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	tr := e.pinned()
	e.signBy(e.write("p2.json", vaultedPolicy(tr, account, 2, alice)), nil, 1)
	if !strings.Contains(e.out.String(), "not yet complete") {
		t.Fatalf("one of 2-of-3 completed: %s", e.out)
	}
	key := e.path("ceremony/custodian-1.key")
	// Each run reloads trust.json, so the commitment has survived a restart.
	if err := e.run("sign", "--key", key, "--draft", e.write("p2x.json", vaultedPolicy(tr, account, 2)), "--out", e.path("o2x")); !errors.Is(err, pqcrypto.ErrEquivocation) {
		t.Fatalf("conflicting same-epoch draft after a partial signature: err %v, want ErrEquivocation", err)
	}
	if err := e.run("sign", "--key", key, "--draft", e.write("p1.json", vaultedPolicy(tr, account, 1, alice)), "--out", e.path("o1")); !errors.Is(err, pqcrypto.ErrRollback) {
		t.Fatalf("lower-epoch draft after a partial signature: err %v, want ErrRollback", err)
	}
	e.signBy(e.write("p3.json", vaultedPolicy(tr, account, 3, alice)), nil, 2)
}

// gatePrompt blocks in Passphrase until released, holding a command mid-flight.
type gatePrompt struct{ entered, release chan struct{} }

func (g *gatePrompt) Passphrase(string, bool) (string, error) {
	close(g.entered)
	<-g.release
	return pass, nil
}
func (g *gatePrompt) Confirm(string) (bool, error) { return true, nil }

func TestStateLockSerializesWriters(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	// A second CLI produces a complete epoch-2 policy for e to import.
	h := newEnv(t)
	h.dir = e.dir
	h.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	ep2 := h.signBy(e.write("p2.json", vaultedPolicy(e.pinned(), account, 2, alice)), nil, 1, 2)

	other := pqcrypto.UUID("0190b2a4-3333-7333-8333-000000000002")
	gate := &gatePrompt{entered: make(chan struct{}), release: make(chan struct{})}
	signer := &App{Home: e.app.Home, Out: &bytes.Buffer{}, Prompt: gate, KDF: cheap}
	importer := &App{Home: e.app.Home, Out: &bytes.Buffer{}, Prompt: e.prompt, KDF: cheap}
	draft := e.write("o.json", vaultedPolicy(e.pinned(), other, 1))
	signed, imported := make(chan error, 1), make(chan error, 1)
	go func() {
		signed <- signer.Run(context.Background(), []string{"sign", "--key", e.path("ceremony/custodian-3.key"),
			"--draft", draft, "--out", e.path("o.out")})
	}()
	<-gate.entered // the signer has loaded the state and waits for its passphrase
	go func() { imported <- importer.Run(context.Background(), []string{"import", ep2}) }()
	select {
	case err := <-imported:
		t.Errorf("import ran while another command held the state (err %v)", err)
		imported <- err
	case <-time.After(200 * time.Millisecond):
	}
	close(gate.release)
	if err := <-signed; err != nil {
		t.Fatal(err)
	}
	if err := <-imported; err != nil {
		t.Fatal(err)
	}
	s, tr, err := e.app.load()
	if err != nil {
		t.Fatal(err)
	}
	if r := tr.Lookup(pqcrypto.TypePolicy, account); r == nil || r.Epoch != 2 {
		t.Fatalf("a stale writer erased the imported epoch: %+v", r)
	}
	if s.commitment(pqcrypto.TypePolicy, other) == nil {
		t.Fatal("the signer's commitment was lost")
	}
}

func TestEnrollStrandsNoKey(t *testing.T) {
	e := newEnv(t)
	fp := e.ceremony("ceremony", "3", "2")
	e.must("trust", fp, "--bundle", e.path("ceremony/bundle.json"))
	if err := os.WriteFile(e.path("taken.key.draft.json"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(e.dir, e.path("alias")); err != nil {
		t.Fatal(err)
	}
	base := []string{"enroll", "--principal-id", string(alice), "--issuer", "https://idp", "--subject", "alice"}
	for name, c := range map[string]struct {
		key, draft, want string
		client           bool
	}{
		"draft-out is key-out":        {key: e.path("a.key"), draft: e.path("a.key"), want: "same file"},
		"draft-out aliases key-out":   {key: e.path("a.key"), draft: e.path("alias/a.key"), want: "same file"},
		"draft directory is missing":  {key: e.path("a.key"), draft: e.path("missing/a.json"), want: "no such file"},
		"key directory is missing":    {key: e.path("missing/a.key"), draft: e.path("a.json"), want: "no such file"},
		"client draft already exists": {key: e.path("taken.key"), client: true, want: "already exists"},
	} {
		e.app.Client = nil
		args := append(base, "--key-out", c.key)
		if c.client {
			e.app.Client = &fakeClient{}
		} else {
			args = append(args, "--draft-out", c.draft)
		}
		if err := e.run(args...); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err %v, want %q before any key exists", name, err, c.want)
		}
		if _, err := os.Lstat(c.key); !os.IsNotExist(err) {
			t.Errorf("%s: a key file was left without its draft", name)
		}
	}
	// A draft that appears between the check and the commit removes the new key.
	if err := os.WriteFile(e.path("late.json"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := createPair(e.path("late.key"), bytes.Repeat([]byte("k"), 64), e.path("late.json"), []byte("d")); err == nil {
		t.Fatal("createPair replaced an existing draft")
	}
	if ents, _ := filepath.Glob(e.path("late.key*")); len(ents) != 0 {
		t.Fatalf("createPair left %v behind", ents)
	}
	e.app.Client = nil
	e.must(append(base, "--key-out", e.path("ok.key"), "--draft-out", e.path("ok.json"))...)
	for p, mode := range map[string]os.FileMode{e.path("ok.key"): 0o600, e.path("ok.json"): 0o644} {
		if info, err := os.Stat(p); err != nil || info.Mode().Perm() != mode {
			t.Fatalf("%s: %v %v, want mode %v", p, info, err, mode)
		}
	}
	if ents, _ := filepath.Glob(e.path("*.tmp")); len(ents) != 0 {
		t.Fatalf("staged files left behind: %v", ents)
	}
}
