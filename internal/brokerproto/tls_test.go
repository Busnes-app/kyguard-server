package brokerproto_test

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// handshake runs one TLS handshake between server and client configurations and returns
// each side's state and error.
func handshake(t *testing.T, server, client *tls.Config) (srv, cli tls.ConnectionState, srvErr, cliErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		a, err := ln.Accept()
		if err != nil {
			srvErr = err
			return
		}
		s := tls.Server(a, server)
		srvErr = s.Handshake()
		srv = s.ConnectionState()
		s.Close()
	}()
	b, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Client(b, client)
	cliErr = c.Handshake()
	cli = c.ConnectionState()
	c.Close()
	<-done
	return srv, cli, srvErr, cliErr
}

func listenerTLS(t *testing.T) (*brokerproto.CA, *tls.Config) {
	t.Helper()
	ca, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.ListenerCert(host)
	if err != nil {
		t.Fatal(err)
	}
	return ca, brokerproto.ServerTLS(ca, leaf)
}

// PQC plan Q9: the broker listener and client negotiate the hybrid X25519MLKEM768.
func TestBrokerTLSNegotiatesTheHybrid(t *testing.T) {
	ca, server := listenerTLS(t)
	srv, cli, srvErr, cliErr := handshake(t, server, brokerproto.ClientTLS(ca.SHA256(), host, nil))
	if srvErr != nil || cliErr != nil {
		t.Fatalf("server %v, client %v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srv)
	pqtls.RequireHybrid(t, cli)
}

// PQC plan Q9: the listener refuses a client offering only classical X25519.
func TestListenerRefusesAClassicalClient(t *testing.T) {
	ca, server := listenerTLS(t)
	client := brokerproto.ClientTLS(ca.SHA256(), host, nil)
	client.CurvePreferences = []tls.CurveID{tls.X25519}
	if _, _, srvErr, cliErr := handshake(t, server, client); srvErr == nil || cliErr == nil {
		t.Fatalf("server %v, client %v", srvErr, cliErr)
	}
}

// PQC plan Q9: the broker client offers only the hybrid, so a listener preferring X25519
// still gets X25519MLKEM768, and one supporting only X25519 is refused.
func TestBrokerClientOffersOnlyTheHybrid(t *testing.T) {
	ca, server := listenerTLS(t)
	server.CurvePreferences = []tls.CurveID{tls.X25519, tls.X25519MLKEM768}
	srv, cli, srvErr, cliErr := handshake(t, server, brokerproto.ClientTLS(ca.SHA256(), host, nil))
	if srvErr != nil || cliErr != nil {
		t.Fatalf("server %v, client %v", srvErr, cliErr)
	}
	pqtls.RequireHybrid(t, srv)
	pqtls.RequireHybrid(t, cli)
	server.CurvePreferences = []tls.CurveID{tls.X25519}
	if _, _, srvErr, cliErr := handshake(t, server, brokerproto.ClientTLS(ca.SHA256(), host, nil)); srvErr == nil || cliErr == nil {
		t.Fatalf("server %v, client %v", srvErr, cliErr)
	}
}

// ClientTLS trades Go's root check for the pin check, so the callback must be installed on
// every configuration it returns and must fail closed: a chain without the pinned CA, a
// certificate issued for client authentication, no hostname to match, or no usable pin.
func TestClientTLSAlwaysInstallsThePinCheck(t *testing.T) {
	ca, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.ListenerCert(host)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range []*tls.Certificate{nil, &leaf} {
		cfg := brokerproto.ClientTLS(ca.SHA256(), host, client)
		if !cfg.InsecureSkipVerify || cfg.VerifyConnection == nil {
			t.Fatalf("client certificate %v: InsecureSkipVerify %v, pin check installed %v",
				client != nil, cfg.InsecureSkipVerify, cfg.VerifyConnection != nil)
		}
	}

	listener, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	broker, err := x509.ParseCertificate(issueBroker(t, ca))
	if err != nil {
		t.Fatal(err)
	}
	verify := func(pin pqcrypto.HexID, hostname string, chain ...*x509.Certificate) error {
		return brokerproto.ClientTLS(pin, hostname, nil).VerifyConnection(tls.ConnectionState{PeerCertificates: chain})
	}
	if err := verify(ca.SHA256(), host, listener, ca.Cert); err != nil {
		t.Fatalf("pinned listener chain: %v", err)
	}
	for name, err := range map[string]error{
		"chain without the CA":       verify(ca.SHA256(), host, listener),
		"client-authentication leaf": verify(ca.SHA256(), host, broker, ca.Cert),
		"no hostname":                verify(ca.SHA256(), "", listener, ca.Cert),
		"no pin":                     verify("", host, listener, ca.Cert),
	} {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func issueBroker(t *testing.T, ca *brokerproto.CA) []byte {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	der, err := ca.IssueBroker(csr, pqcrypto.UUID("01960000-0000-7000-8000-00000000000b"))
	if err != nil {
		t.Fatal(err)
	}
	return der
}
