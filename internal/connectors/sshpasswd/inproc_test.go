package sshpasswd_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/connectors/sshpasswd"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// inproc is an in-process SSH server for behaviour no real sshd shows on demand.
type inproc struct {
	addr        string
	hostKey     string
	submissions atomic.Int32
}

func newInproc(t *testing.T, accept bool, hang bool) *inproc {
	t.Helper()
	_, k, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(k)
	sum := sha256.Sum256(signer.PublicKey().Marshal())
	s := &inproc{hostKey: hex.EncodeToString(sum[:])}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) {
			s.submissions.Add(1)
			if accept {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		KeyboardInteractiveCallback: func(_ ssh.ConnMetadata, ch ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			for range 3 { // keep asking, as a PAM stack may
				if _, err := ch("", "", []string{"Password: "}, []bool{false}); err != nil {
					return nil, err
				}
				s.submissions.Add(1)
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, creqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range creqs {
							r.Reply(true, nil) // accept exec and never answer it when hang
							if !hang {
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	return s
}

func (s *inproc) connector(timeout time.Duration) *sshpasswd.Connector {
	return &sshpasswd.Connector{Timeout: timeout, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.addr)
	}}
}

func (s *inproc) descriptor() *pqcrypto.TargetDescriptor {
	return &pqcrypto.TargetDescriptor{ConnectorType: pqcrypto.ConnectorSSHPasswd, AuthenticatedTargetIdentity: "svc",
		Endpoint: pqcrypto.Endpoint{Host: "db1.kyg.test", Port: 22, SSHHostKeySHA256: s.hostKey}}
}

// §4.6 (security review of #14): a server offering password and keyboard-interactive gets
// the credential once; a rejection is ErrAuthFailed with no second submission.
func TestRejectedCredentialIsSubmittedOnce(t *testing.T) {
	s := newInproc(t, false, false)
	_, err := s.connector(5*time.Second).Login(context.Background(), s.descriptor(), []byte("stale-Passw0rd"))
	if !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
	if n := s.submissions.Load(); n != 1 {
		t.Fatalf("%d credential submissions", n)
	}
}

// Security review of #14: a remote command that never exits cannot stall the broker.
func TestPasswordAgeIsBoundedByTheTimeout(t *testing.T) {
	s := newInproc(t, true, true)
	sess, err := s.connector(300*time.Millisecond).Login(context.Background(), s.descriptor(), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	start := time.Now()
	if _, _, err := sess.(broker.AgeReporter).PasswordAge(context.Background()); err == nil {
		t.Fatal("a hung chage returned a result")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("took %v", d)
	}
}
