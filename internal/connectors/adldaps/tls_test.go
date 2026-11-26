package adldaps_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyguard-server/internal/connectors/adldaps"
	"github.com/Busnes-app/kyguard-server/internal/connectors/connectortest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// startTLSBindDC listens over TLS with the given optional server config mutation, records
// each completed handshake's ConnectionState, and answers one LDAP BindRequest with success.
func startTLSBindDC(t *testing.T, mutate func(*tls.Config)) (addr, caPEM string, states <-chan tls.ConnectionState) {
	t.Helper()
	dir := t.TempDir()
	ca, err := connectortest.TLSFiles(dir, dcHost)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	if mutate != nil {
		mutate(cfg)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan tls.ConnectionState, 4)
	go func() {
		for {
			raw, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer raw.Close()
				tc := tls.Server(raw, cfg)
				if err := tc.Handshake(); err != nil {
					return
				}
				ch <- tc.ConnectionState()
				buf := make([]byte, 4096)
				if _, err := tc.Read(buf); err != nil {
					return
				}
				// BindResponse, message 1, success.
				_, _ = tc.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
				_, _ = tc.Read(buf)
			}()
		}
	}()
	return ln.Addr().String(), ca, ch
}

// PQC W0 row 14: outbound LDAPS negotiates the hybrid X25519MLKEM768 with a capable peer
// (both normally and under GODEBUG=fips140=on), logs the negotiated group, and never logs
// credentials.
func TestLDAPSNegotiatesHybridAndLogsGroup(t *testing.T) {
	addr, caPEM, states := startTLSBindDC(t, nil)
	conn := &adldaps.Connector{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	desc := &pqcrypto.TargetDescriptor{
		DescriptorVersion:           "1",
		ConnectorType:               pqcrypto.ConnectorADLDAPS,
		AuthenticatedTargetIdentity: adminDN,
		Endpoint:                    pqcrypto.Endpoint{Host: dcHost, Port: 636, TLSCAPEM: caPEM},
	}
	secret := "secret-ldaps-password-must-not-appear-in-logs"

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	sess, err := conn.Login(context.Background(), desc, []byte(secret))
	log.SetOutput(prev)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer sess.Close()

	select {
	case st := <-states:
		pqtls.RequireHybrid(t, st)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server handshake state")
	}

	got := logs.String()
	for _, want := range []string{"[ADLDAPS]", dcHost + ":636", "TLS 1.3", "group=X25519MLKEM768"} {
		if !strings.Contains(got, want) {
			t.Errorf("log %q missing %q", got, want)
		}
	}
	if strings.Contains(got, secret) {
		t.Errorf("LDAPS log leaked credential")
	}
}

// PQC W0 row 14: an Active Directory DC that only supports classical ECDHE (CurveP256,
// permitted both normally and under GODEBUG=fips140=on) still connects and logs its
// negotiated group.
func TestLDAPSLogsClassicalGroupWhenPeerLacksHybrid(t *testing.T) {
	addr, caPEM, states := startTLSBindDC(t, func(cfg *tls.Config) {
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
	})
	conn := &adldaps.Connector{
		Timeout: 5 * time.Second,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}
	desc := &pqcrypto.TargetDescriptor{
		DescriptorVersion:           "1",
		ConnectorType:               pqcrypto.ConnectorADLDAPS,
		AuthenticatedTargetIdentity: adminDN,
		Endpoint:                    pqcrypto.Endpoint{Host: dcHost, Port: 636, TLSCAPEM: caPEM},
	}

	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	sess, err := conn.Login(context.Background(), desc, []byte(startPw))
	log.SetOutput(prev)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	defer sess.Close()

	select {
	case st := <-states:
		if st.CurveID != tls.CurveP256 {
			t.Fatalf("CurveID = %v, want CurveP256", st.CurveID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server handshake state")
	}

	got := logs.String()
	if !strings.Contains(got, "group=CurveP256") {
		t.Errorf("log %q missing negotiated classical group", got)
	}
	if strings.Contains(got, startPw) {
		t.Errorf("LDAPS log leaked credential")
	}
}
