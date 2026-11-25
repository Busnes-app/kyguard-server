package brokerproto_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

const host = brokertest.Host

type fixture struct {
	*brokertest.CP
	t    *testing.T
	st   store.Store
	dep  *pqtest.Deployment
	ca   *brokerproto.CA
	l    *brokerproto.Listener
	srv  *httptest.Server
	pool string
}

func newFixture(t *testing.T) *fixture {
	c := brokertest.NewCP(t)
	return &fixture{CP: c, t: t, st: c.Store, dep: c.Dep, ca: c.CA, l: c.L, srv: c.Srv, pool: string(c.Pool)}
}

func (f *fixture) serve(hostname string) *httptest.Server { return f.Serve(hostname) }

func (f *fixture) token(srv *httptest.Server, ttl time.Duration) *brokerproto.Token {
	f.t.Helper()
	tok, err := brokerproto.ParseToken(f.Token(srv, ttl))
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

type brokerKeys struct {
	tls ed25519.PrivateKey
	sig *pqcrypto.SigningKey
	enc recoverykey.PrivateKey
}

func newKeys(t *testing.T) *brokerKeys {
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return &brokerKeys{k, sig, enc}
}

func (f *fixture) pair(tok *brokerproto.Token, k *brokerKeys) (*brokerproto.Paired, error) {
	return brokerproto.Pair(context.Background(), tok, f.dep.Fingerprint, k.tls, k.sig.Public(), k.enc.Public().Bytes())
}

func (f *fixture) mustPair() (*brokerproto.Paired, *brokerKeys) {
	f.t.Helper()
	k := newKeys(f.t)
	p, err := f.pair(f.token(f.srv, 10*time.Minute), k)
	if err != nil {
		f.t.Fatal(err)
	}
	return p, k
}

func TestPairingIssuesACertificateAndTheBundle(t *testing.T) {
	f := newFixture(t)
	p, k := f.mustPair()
	if p.Trust.DeploymentID() != f.dep.ID {
		t.Fatalf("deployment %s", p.Trust.DeploymentID())
	}
	b, err := f.st.Guard().GetBroker(context.Background(), string(p.BrokerID))
	if err != nil {
		t.Fatal(err)
	}
	sid, _ := k.sig.Public().SigKeyID()
	if audits(t, f.st, "pairing.outcome_unknown") != 0 {
		t.Fatal("a delivered response was recorded as lost")
	}
	if n, err := f.st.Guard().ExpirePendingIntents(context.Background(), "pairing", time.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("delivered pairing left pending: %d %v", n, err)
	}
	if b.PoolID != f.pool || b.CertSHA256 != string(brokerproto.CertSHA256(p.Cert.Raw)) || b.SigKeyID != string(sid) ||
		b.EncKeyID != k.enc.Public().ID() || b.CASHA256 != string(f.ca.SHA256()) {
		t.Fatalf("stored broker %+v", b)
	}
}

func TestPairingTokenIsOneTime(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.srv, 10*time.Minute)
	if _, err := f.pair(tok, newKeys(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pair(tok, newKeys(t)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("reused token: %v", err)
	}
	if _, err := f.pair(f.token(f.srv, -time.Second), newKeys(t)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expired token: %v", err)
	}
}

func TestPairingRefusesAWrongBundleFingerprint(t *testing.T) {
	f := newFixture(t)
	k := newKeys(t)
	other := pqtest.New(t)
	_, err := brokerproto.Pair(context.Background(), f.token(f.srv, time.Minute), other.Fingerprint, k.tls, k.sig.Public(), k.enc.Public().Bytes())
	if !errors.Is(err, pqcrypto.ErrFingerprint) {
		t.Fatalf("got %v", err)
	}
}

// §13 1A acceptance test 7: a listener certificate without KY_BROKER_HOSTNAME is refused.
func TestBrokerRefusesAListenerWithoutItsHostname(t *testing.T) {
	f := newFixture(t)
	wrong := f.serve("other.example.test")
	u, _ := url.Parse(wrong.URL)
	tok := f.token(wrong, time.Minute)
	tok.URL = "https://" + u.Host // dialled as 127.0.0.1, certificate names other.example.test
	if _, err := f.pair(tok, newKeys(t)); err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("got %v", err)
	}
}

// The TLS layer itself pins the CA: a client pinning another CA fails the handshake.
func TestClientTLSPinsTheCA(t *testing.T) {
	f := newFixture(t)
	other, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for pin, ok := range map[pqcrypto.HexID]bool{f.ca.SHA256(): true, other.SHA256(): false} {
		hc := &http.Client{Transport: &http.Transport{TLSClientConfig: brokerproto.ClientTLS(pin, host, nil)}}
		resp, err := hc.Get(f.srv.URL + "/")
		if err == nil {
			resp.Body.Close()
		}
		if (err == nil) != ok {
			t.Fatalf("pin %s: %v", pin, err)
		}
		if !ok && !errors.Is(err, brokerproto.ErrPinnedCA) {
			t.Fatalf("pin %s: %v", pin, err)
		}
	}
}

func TestBrokerRefusesAnotherCA(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.srv, time.Minute)
	other, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	tok.CASHA256 = other.SHA256()
	if _, err := f.pair(tok, newKeys(t)); !errors.Is(err, brokerproto.ErrPinnedCA) {
		t.Fatalf("got %v", err)
	}
}

// failingWriter loses the response, as a dropped connection would.
type failingWriter struct{ h http.Header }

func (w *failingWriter) Header() http.Header       { return w.h }
func (w *failingWriter) Write([]byte) (int, error) { return 0, errors.New("connection reset") }
func (w *failingWriter) WriteHeader(int)           {}
func (w *failingWriter) FlushError() error         { return errors.New("connection reset") }

// §13 Phase 0 acceptance test 12: a pairing token consumed with its response lost ends
// outcome_unknown.
func TestLostPairingResponseEndsOutcomeUnknown(t *testing.T) {
	f := newFixture(t)
	tok := f.token(f.srv, time.Minute)
	k := newKeys(t)
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k.tls)
	body, _ := canonical.Marshal(brokerproto.PairRequest{Secret: tok.Secret, CSR: csr, SigPub: k.sig.Public(), EncPub: k.enc.Public().Bytes(), Version: "0.1.0"})
	req := httptest.NewRequest(http.MethodPost, brokerproto.PathPair, bytes.NewReader(body))
	f.l.Handler().ServeHTTP(&failingWriter{h: http.Header{}}, req)
	if n := audits(t, f.st, "pairing.outcome_unknown"); n != 1 {
		t.Fatalf("%d outcome_unknown records", n)
	}
	// Not pending any more: startup reconciliation finds nothing to settle.
	if n, err := f.st.Guard().ExpirePendingIntents(context.Background(), "pairing", time.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("still pending: %d %v", n, err)
	}
	if _, err := f.pair(tok, newKeys(t)); err == nil {
		t.Fatal("the consumed token paired again")
	}
}

func audits(t *testing.T, st store.Store, action string) int {
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

func (f *fixture) admitPool(epoch pqcrypto.Counter, members ...pqcrypto.BrokerMember) {
	f.AdmitPool(epoch, members...)
}

func member(p *brokerproto.Paired, k *brokerKeys, status string) pqcrypto.BrokerMember {
	b := &pqtest.Broker{ID: p.BrokerID, Sig: k.sig, Enc: k.enc, CertSHA256: brokerproto.CertSHA256(p.Cert.Raw)}
	return b.Member(status)
}

func clientCert(p *brokerproto.Paired, k *brokerKeys) tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{p.Cert.Raw}, PrivateKey: k.tls}
}

func dial(f *fixture, p *brokerproto.Paired, cert tls.Certificate) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := brokerproto.Dial(ctx, f.srv.URL, p.CACert, cert)
	if err != nil {
		return err
	}
	c.CloseNow()
	return nil
}

// §13 1A acceptance test 7 and §4.1: the channel admits only an internal-CA certificate of a
// broker that is active, with that certificate, in its pool's current manifest.
func TestChannelAdmitsOnlyActiveBrokers(t *testing.T) {
	f := newFixture(t)
	p, k := f.mustPair()

	// No client certificate.
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: brokerproto.ClientTLS(f.ca.SHA256(), host, nil)}}
	resp, err := hc.Get(f.srv.URL + brokerproto.PathChannel)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("no certificate: %d", resp.StatusCode)
	}

	// Paired, but no Custodian-signed pool manifest yet.
	if err := dial(f, p, clientCert(p, k)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("before the pool manifest: %v", err)
	}

	f.admitPool(1, member(p, k, pqcrypto.StatusActive))
	if err := dial(f, p, clientCert(p, k)); err != nil {
		t.Fatalf("active broker: %v", err)
	}

	// The same broker_id under a certificate from another CA fails the TLS handshake.
	other, _ := brokerproto.CreateCA(t.TempDir())
	forged := forgeCert(t, other, p.BrokerID, k.tls)
	if err := dial(f, p, forged); err == nil {
		t.Fatal("foreign CA admitted")
	}

	// Revoked: refused (the Control Plane refuses the old broker's certificate, §4.1).
	p2, k2 := f.mustPair()
	f.admitPool(2, member(p, k, pqcrypto.StatusRevoked), member(p2, k2, pqcrypto.StatusActive))
	if err := dial(f, p, clientCert(p, k)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("revoked broker: %v", err)
	}
	if err := dial(f, p2, clientCert(p2, k2)); err != nil {
		t.Fatalf("replacement broker: %v", err)
	}
}

func TestChannelRefusesACertificateOtherThanTheListedOne(t *testing.T) {
	f := newFixture(t)
	p, k := f.mustPair()
	m := member(p, k, pqcrypto.StatusActive)
	m.MTLSCertSHA256 = brokerproto.CertSHA256([]byte("another certificate"))
	f.admitPool(1, m)
	if err := dial(f, p, clientCert(p, k)); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("got %v", err)
	}
}

func TestChannelRefusesOldBrokerVersions(t *testing.T) {
	f := newFixture(t)
	p, k := f.mustPair()
	f.admitPool(1, member(p, k, pqcrypto.StatusActive))
	f.l.MinVersion = "9.0.0"
	if err := dial(f, p, clientCert(p, k)); err == nil || !strings.Contains(err.Error(), "426") {
		t.Fatalf("got %v", err)
	}
}

func TestVersionAtLeast(t *testing.T) {
	for _, c := range []struct {
		v, min string
		ok     bool
	}{{"0.1.0", "0.1.0", true}, {"0.2.0", "0.1.9", true}, {"1.0.0", "0.9.9", true}, {"0.1.0", "0.1.1", false},
		{"", "0.1.0", false}, {"0.1", "0.1.0", false}, {"0.01.0", "0.1.0", false}, {"0.1.0-rc1", "0.1.0", false}, {"-1.0.0", "0.0.0", false}} {
		if got := brokerproto.VersionAtLeast(c.v, c.min); got != c.ok {
			t.Errorf("%q >= %q: %v", c.v, c.min, got)
		}
	}
}

func forgeCert(t *testing.T, ca *brokerproto.CA, id pqcrypto.UUID, key ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	csr, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x"}}, key)
	der, err := ca.IssueBroker(csr, id)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestLoadCARefusesAKeyForAnotherCertificate(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	if _, err := brokerproto.CreateCA(a); err != nil {
		t.Fatal(err)
	}
	if _, err := brokerproto.CreateCA(b); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(b+"/"+brokerproto.CACertFile, a+"/"+brokerproto.CACertFile); err != nil {
		t.Fatal(err)
	}
	if _, err := brokerproto.LoadCA(a); !errors.Is(err, brokerproto.ErrCAMismatch) {
		t.Fatalf("got %v", err)
	}
	if _, err := brokerproto.CreateCA(b); err == nil {
		t.Fatal("CreateCA replaced an existing CA")
	}
}

func copyFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o644)
}
