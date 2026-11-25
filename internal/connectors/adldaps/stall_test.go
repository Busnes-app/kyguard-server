package adldaps_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/connectors/adldaps"
	"github.com/Busnes-app/kyguard-server/internal/connectors/connectortest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// stallDC completes TLS, answers the first bind with success only when bindOK, and then
// never answers again. after counts the bytes it receives after that bind; ended gets one value
// per connection that answered a bind, once it closes.
type stallDC struct {
	addr, caPEM string
	after       atomic.Int64
	ended       chan struct{}
}

func newStallDC(t *testing.T, bindOK bool) *stallDC {
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
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &stallDC{addr: ln.Addr().String(), caPEM: ca, ended: make(chan struct{}, 16)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				if bindOK {
					// BindResponse, message 1, success.
					c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00})
					defer func() { s.ended <- struct{}{} }()
				}
				for {
					n, err := c.Read(buf)
					s.after.Add(int64(n))
					if err != nil {
						return
					}
				}
			}()
		}
	}()
	return s
}

func (s *stallDC) connector() *adldaps.Connector {
	return &adldaps.Connector{Timeout: 5 * time.Second, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.addr)
	}}
}

func (s *stallDC) descriptor() *pqcrypto.TargetDescriptor {
	return &pqcrypto.TargetDescriptor{DescriptorVersion: "1", ConnectorType: pqcrypto.ConnectorADLDAPS, AuthenticatedTargetIdentity: adminDN,
		Endpoint: pqcrypto.Endpoint{Host: dcHost, Port: 636, TLSCAPEM: s.caPEM}}
}

// bounded runs op with a context cancelled after 200 ms and fails unless it returns an
// error well before the connector's 5 s timeout.
func bounded(t *testing.T, name string, op func(ctx context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	time.AfterFunc(200*time.Millisecond, cancel)
	start := time.Now()
	err := op(ctx)
	if d := time.Since(start); err == nil || d > 3*time.Second {
		t.Fatalf("%s: %v after %v", name, err, d)
	}
}

// PR #13 review: every LDAP operation after the TLS handshake ends on cancellation, not at
// the connector's fixed timeout, while the directory does not answer.
func TestOperationsObserveCancellation(t *testing.T) {
	pw := []byte(startPw)
	stalled := newStallDC(t, false)
	bounded(t, "login", func(ctx context.Context) error {
		_, err := stalled.connector().Login(ctx, stalled.descriptor(), pw)
		return err
	})
	bounded(t, "verify", func(ctx context.Context) error {
		return stalled.connector().Verify(ctx, stalled.descriptor(), pw, "pwdLastSet=1 kvno=1")
	})
	s := newStallDC(t, true)
	session := func() broker.Session {
		sess, err := s.connector().Login(context.Background(), s.descriptor(), pw)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { sess.Close() })
		return sess
	}
	bounded(t, "baseline", func(ctx context.Context) error { _, err := session().Baseline(ctx); return err })
	bounded(t, "password age", func(ctx context.Context) error {
		_, _, err := session().(broker.AgeReporter).PasswordAge(ctx)
		return err
	})
	bounded(t, "change", func(ctx context.Context) error {
		return session().Change(ctx, pw, []byte(otherPw), func() error { return nil })
	})
}

// PR #13 review: a cancellation that arrives while the intent commits stops the modify
// from starting.
func TestNoModifyAfterCancellation(t *testing.T) {
	s := newStallDC(t, true)
	sess, err := s.connector().Login(context.Background(), s.descriptor(), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	ctx, cancel := context.WithCancel(context.Background())
	err = sess.Change(ctx, []byte(startPw), []byte(otherPw), func() error { cancel(); return nil })
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("change: %v", err)
	}
	sess.Close()
	<-s.ended // the server has read everything that was sent
	if n := s.after.Load(); n != 0 {
		t.Fatalf("%d bytes reached the directory after the cancellation", n)
	}
}
