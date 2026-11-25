// Package brokertest runs a Control Plane broker listener in-process for tests: a store with
// an imported bundle, a broker CA, one pool and the listener on a local TLS port. Import it
// from _test.go files only.
package brokertest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

// Host is the hostname the listener certificate names; the listener binds it.
const Host = "127.0.0.1"

// CP is the Control Plane side.
type CP struct {
	T     testing.TB
	Store store.Store
	Dep   *pqtest.Deployment
	CA    *brokerproto.CA
	L     *brokerproto.Listener
	Srv   *httptest.Server
	Pool  pqcrypto.UUID
}

// NewCP starts a listener for Host.
func NewCP(t *testing.T) *CP {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ca, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c := &CP{T: t, Store: st, Dep: pqtest.New(t), CA: ca, Pool: pqtest.UUID()}
	if err := st.Guard().ImportBundle(ctx, &store.BootstrapBundle{DeploymentID: string(c.Dep.ID), Fingerprint: string(c.Dep.Fingerprint), Bundle: c.Dep.Bundle}, "host"); err != nil {
		t.Fatal(err)
	}
	if err := st.Guard().CreatePool(ctx, &store.BrokerPool{ID: string(c.Pool), Name: "pool", CreatedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatal(err)
	}
	c.L = &brokerproto.Listener{Store: st, Trust: cptrust.New(st), CA: ca, MinVersion: "0.1.0"}
	c.Srv = c.Serve(Host)
	return c
}

// Serve starts another listener whose certificate names hostname.
func (c *CP) Serve(hostname string) *httptest.Server {
	c.T.Helper()
	leaf, err := c.CA.ListenerCert(hostname)
	if err != nil {
		c.T.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(c.L.Handler())
	srv.TLS = brokerproto.ServerTLS(c.CA, leaf)
	srv.StartTLS()
	c.T.Cleanup(srv.Close)
	return srv
}

// Token mints a pairing token for srv valid for ttl and returns its string form.
func (c *CP) Token(srv *httptest.Server, ttl time.Duration) string {
	c.T.Helper()
	secret := make([]byte, 32)
	rand.Read(secret)
	now := time.Now().UTC()
	if err := c.Store.Guard().CreatePairingToken(context.Background(), &store.PairingToken{TokenHash: brokerproto.HashSecret(secret), PoolID: string(c.Pool), CreatedBy: "admin", CreatedAt: now, ExpiresAt: now.Add(ttl)}, nil); err != nil {
		c.T.Fatal(err)
	}
	s, err := brokerproto.Token{CASHA256: c.CA.SHA256(), Secret: secret, URL: srv.URL}.Encode()
	if err != nil {
		c.T.Fatal(err)
	}
	return s
}

// AdmitPool submits a Custodian-signed manifest for the pool.
func (c *CP) AdmitPool(epoch pqcrypto.Counter, members ...pqcrypto.BrokerMember) []byte {
	c.T.Helper()
	raw := c.Dep.Pool(c.T, c.Pool, epoch, members, nil)
	if _, _, err := c.L.Trust.Submit(context.Background(), raw, "custodian", ""); err != nil {
		c.T.Fatal(err)
	}
	return raw
}

// Broker is a paired test broker driven directly over the channel.
type Broker struct {
	ID     pqcrypto.UUID
	TLS    ed25519.PrivateKey
	Sig    *pqcrypto.SigningKey
	Enc    recoverykey.PrivateKey
	Paired *brokerproto.Paired
	Conn   *brokerproto.Conn
}

// PairBroker pairs a new broker against the listener; it is not admitted until AdmitPool
// lists it.
func (c *CP) PairBroker() *Broker {
	c.T.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	sig, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		c.T.Fatal(err)
	}
	enc, err := recoverykey.Generate()
	if err != nil {
		c.T.Fatal(err)
	}
	tok, err := brokerproto.ParseToken(c.Token(c.Srv, time.Minute))
	if err != nil {
		c.T.Fatal(err)
	}
	p, err := brokerproto.Pair(context.Background(), tok, c.Dep.Fingerprint, k, sig.Public(), enc.Public().Bytes())
	if err != nil {
		c.T.Fatal(err)
	}
	return &Broker{ID: p.BrokerID, TLS: k, Sig: sig, Enc: enc, Paired: p}
}

// Member lists b in a pool manifest.
func (b *Broker) Member(status string) pqcrypto.BrokerMember {
	return (&pqtest.Broker{ID: b.ID, Sig: b.Sig, Enc: b.Enc, CertSHA256: brokerproto.CertSHA256(b.Paired.Cert.Raw)}).Member(status)
}

// Dial opens the channel; it fails unless the broker is admitted.
func (c *CP) Dial(b *Broker) error {
	ctx, cancel := context.WithCancel(context.Background())
	ws, err := brokerproto.Dial(ctx, c.Srv.URL, b.Paired.CACert, tls.Certificate{Certificate: [][]byte{b.Paired.Cert.Raw}, PrivateKey: b.TLS})
	if err != nil {
		cancel()
		return err
	}
	b.Conn = brokerproto.NewConn(ctx, ws)
	c.T.Cleanup(cancel)
	return nil
}

// Account creates a managed account in the pool with an SSH descriptor and a signed policy
// at epoch 1, and returns the policy (mutated by edit before signing, if given).
func (c *CP) Account(edit func(*pqcrypto.PolicyManifest)) *pqcrypto.PolicyManifest {
	c.T.Helper()
	ctx := context.Background()
	acct, asset := pqtest.UUID(), pqtest.UUID()
	v := c.Store.Vault()
	if err := v.CreateAsset(ctx, &store.Asset{ID: string(asset), Name: "host"}); err != nil {
		c.T.Fatal(err)
	}
	if err := v.CreateAccount(ctx, &store.Account{ID: string(acct), AssetID: string(asset), Name: "svc", AccountKind: pqcrypto.KindManaged, PoolID: string(c.Pool)}); err != nil {
		c.T.Fatal(err)
	}
	raw, dg := c.Dep.SSHTarget(c.T, acct, asset, "db1.example.test", 22, "svc", pqcrypto.HexID(strings.Repeat("ab", 32)))
	if err := v.PutTargetDescriptor(ctx, string(dg), string(acct), raw); err != nil {
		c.T.Fatal(err)
	}
	p := c.Dep.ManagedPolicy(acct, c.Pool, 1, dg)
	if edit != nil {
		edit(p)
	}
	c.Submit(c.Dep.Signed(c.T, p))
	return p
}

// Submit admits a signed manifest on the Control Plane.
func (c *CP) Submit(raw []byte) {
	c.T.Helper()
	if _, _, err := c.L.Trust.Submit(context.Background(), raw, "custodian", ""); err != nil {
		c.T.Fatal(err)
	}
}
