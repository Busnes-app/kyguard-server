// Package brokertest runs a Control Plane broker listener in-process for tests: a store with
// an imported bundle, a broker CA, one pool and the listener on a local TLS port. Import it
// from _test.go files only.
package brokertest

import (
	"context"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

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
