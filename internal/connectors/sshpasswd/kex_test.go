package sshpasswd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/fips140"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Busnes-app/kyguard-server/internal/connectors/sshpasswd"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// kexServer accepts any password over exactly the given key exchanges and reports the one
// each connection negotiated, read from the server's side of the connection.
func kexServer(t *testing.T, kexs ...string) (*sshpasswd.Connector, *pqcrypto.TargetDescriptor, <-chan string) {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(k)
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	got := make(chan string, 8)
	cfg := &ssh.ServerConfig{
		Config: ssh.Config{KeyExchanges: kexs},
		PasswordCallback: func(md ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			got <- md.(ssh.AlgorithmsConnMetadata).Algorithms().KeyExchange
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for nc := range chans {
						nc.Reject(ssh.Prohibited, "no channels")
					}
				}()
				sc.Wait()
			}()
		}
	}()
	conn := &sshpasswd.Connector{Timeout: 5 * time.Second, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}}
	d := &pqcrypto.TargetDescriptor{ConnectorType: pqcrypto.ConnectorSSHPasswd, AuthenticatedTargetIdentity: "svc",
		Endpoint: pqcrypto.Endpoint{Host: "db1.kyg.test", Port: 22, SSHHostKeySHA256: hex.EncodeToString(sum[:])}}
	return conn, d, got
}

// PQC W0: the connector negotiates each key exchange it lists, the hybrid ML-KEM first.
func TestKeyExchangeNegotiated(t *testing.T) {
	for _, offer := range [][]string{
		// A server offering the hybrid and classical ECDH gets the hybrid.
		{ssh.KeyExchangeCurve25519, ssh.KeyExchangeECDHP256, ssh.KeyExchangeMLKEM768X25519},
		{ssh.KeyExchangeCurve25519},
		{"curve25519-sha256@libssh.org"},
		{ssh.KeyExchangeECDHP256},
		{ssh.KeyExchangeECDHP384},
		{ssh.KeyExchangeECDHP521},
	} {
		want := offer[len(offer)-1]
		t.Run(want, func(t *testing.T) {
			if fips140.Enabled() && strings.HasPrefix(want, "curve25519") {
				t.Skip("x/crypto registers no curve25519 key exchange under fips140=on")
			}
			conn, d, got := kexServer(t, offer...)
			sess, err := conn.Login(context.Background(), d, []byte("pw"))
			if err != nil {
				t.Fatal(err)
			}
			sess.Close()
			if kex := <-got; kex != want {
				t.Fatalf("negotiated %s, want %s", kex, want)
			}
		})
	}
}

// PQC W0: a server offering only SHA-1 (or another unlisted) key exchange is refused before
// any credential is sent.
func TestKeyExchangeWithoutAListedAlgorithmIsRefused(t *testing.T) {
	for _, kex := range []string{ssh.InsecureKeyExchangeDH14SHA1, ssh.InsecureKeyExchangeDH1SHA1, ssh.KeyExchangeDH14SHA256} {
		t.Run(kex, func(t *testing.T) {
			conn, d, got := kexServer(t, kex)
			if sess, err := conn.Login(context.Background(), d, []byte("pw")); err == nil {
				sess.Close()
				t.Fatalf("logged in over %s", kex)
			}
			select {
			case k := <-got:
				t.Fatalf("credential sent over %s", k)
			default:
			}
		})
	}
}
