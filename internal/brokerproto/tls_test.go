package brokerproto_test

import (
	"crypto/tls"
	"net"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
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
