package adldaps_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/broker/brokerrig"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/connectors/adldaps"
	"github.com/Busnes-app/kyguard-server/internal/connectors/connectortest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

const (
	dcHost   = "dc1.kyg.test"
	baseDN   = "CN=Users,DC=kyg,DC=test"
	adminDN  = "CN=Administrator," + baseDN
	adminPw  = "Admin-Passw0rd!"
	startPw  = "Start-Passw0rd-1!"
	otherPw  = "Other-Passw0rd-2!"
	sambaTag = "kyguard-test-samba:1"
)

var dc struct {
	c     *connectortest.Container
	addr  string // 127.0.0.1:port mapped to 636
	caPEM string
	err   error
}

func TestMain(m *testing.M) {
	if connectortest.Enabled() {
		dc.err = startDC()
	}
	code := m.Run()
	if dc.c != nil {
		dc.c.Stop()
	}
	os.Exit(code)
}

func startDC() error {
	dir, err := os.MkdirTemp("", "kyg-samba-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	if dc.caPEM, err = connectortest.TLSFiles(dir, dcHost); err != nil {
		return err
	}
	c, err := connectortest.Start(sambaTag, filepath.Join("testdata", "samba"), map[string]string{dir + "/.": "/tls/"},
		"--hostname", "dc1", "--cap-add", "SYS_ADMIN", "-p", "127.0.0.1::636")
	if err != nil {
		return err
	}
	dc.c = c
	if err := connectortest.WaitFor(3*time.Minute, func() error {
		_, err := c.Exec("test", "-f", "/tmp/provisioned")
		return err
	}); err != nil {
		return fmt.Errorf("samba never provisioned: %w", err)
	}
	if dc.addr, err = c.Port("636/tcp"); err != nil {
		return err
	}
	return connectortest.WaitFor(2*time.Minute, adminLogin)
}

// need skips without Docker and fails if the DC did not start.
func need(t *testing.T) {
	t.Helper()
	if !connectortest.Enabled() {
		t.Skip("set KY_TEST_DOCKER=1 to run against Samba AD")
	}
	if dc.err != nil {
		t.Fatalf("samba: %v", dc.err)
	}
}

func connector() *adldaps.Connector {
	return &adldaps.Connector{Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != net.JoinHostPort(dcHost, "636") {
			return nil, fmt.Errorf("dial outside the descriptor: %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, dc.addr)
	}}
}

func adminLogin() error {
	s, err := connector().Login(context.Background(), descriptor(adminDN), []byte(adminPw))
	if err != nil {
		return err
	}
	return s.Close()
}

func samba(t *testing.T, args ...string) string {
	t.Helper()
	out, err := dc.c.Exec(append([]string{"samba-tool"}, args...)...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// minAge sets the domain's minimum password age in days.
func minAge(t *testing.T, days int) {
	samba(t, "domain", "passwordsettings", "set", fmt.Sprintf("--min-pwd-age=%d", days))
}

var userN int

// newUser creates a fresh account and returns its DN.
func newUser(t *testing.T) string {
	t.Helper()
	userN++
	name := fmt.Sprintf("svc%d-%d", time.Now().UnixNano()%100000, userN)
	samba(t, "user", "create", name, startPw)
	return "CN=" + name + "," + baseDN
}

func descriptor(dn string) *pqcrypto.TargetDescriptor {
	return &pqcrypto.TargetDescriptor{DescriptorVersion: "1", ConnectorType: pqcrypto.ConnectorADLDAPS, AuthenticatedTargetIdentity: dn,
		Endpoint: pqcrypto.Endpoint{Host: dcHost, Port: 636, TLSCAPEM: dc.caPEM}}
}

func badPwdCount(t *testing.T, dn string) string {
	t.Helper()
	out := samba(t, "user", "show", strings.TrimPrefix(strings.SplitN(dn, ",", 2)[0], "CN="), "--attributes=badPwdCount")
	for _, l := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(l, "badPwdCount: "); ok {
			return v
		}
	}
	return "0"
}

func TestLoginAndAuthFailure(t *testing.T) {
	need(t)
	dn := newUser(t)
	s, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	if b, err := s.Baseline(context.Background()); err != nil || !strings.HasPrefix(b, "pwdLastSet=") {
		t.Fatalf("baseline %q %v", b, err)
	}
	s.Close()
	if _, err := connector().Login(context.Background(), descriptor(dn), []byte("wrong-Passw0rd")); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("wrong password: %v", err)
	}
	if n := badPwdCount(t, dn); n != "1" {
		t.Fatalf("badPwdCount %s: one wrong bind must be exactly one failed attempt", n)
	}
	if _, err := connector().Login(context.Background(), descriptor(dn), nil); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("empty password: %v", err)
	}
}

// §13 1A acceptance test 7: a wrong LDAPS CA fails the TLS handshake; so does a certificate
// for another host name.
func TestWrongCAOrHostFailsTheHandshake(t *testing.T) {
	need(t)
	dn := newUser(t)
	other, err := connectortest.TLSFiles(t.TempDir(), dcHost)
	if err != nil {
		t.Fatal(err)
	}
	d := descriptor(dn)
	d.Endpoint.TLSCAPEM = other
	_, err = connector().Login(context.Background(), d, []byte(startPw))
	var uerr x509UnknownAuthority
	if err == nil || !uerr.is(err) {
		t.Fatalf("wrong CA: %v", err)
	}
	c := &adldaps.Connector{Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, dc.addr)
	}}
	d = descriptor(dn)
	d.Endpoint.Host = "dc2.kyg.test"
	if _, err := c.Login(context.Background(), d, []byte(startPw)); err == nil || !strings.Contains(err.Error(), "dc2.kyg.test") {
		t.Fatalf("wrong host: %v", err)
	}
	if n := badPwdCount(t, dn); n != "0" {
		t.Fatalf("a refused handshake still reached a bind: badPwdCount %s", n)
	}
}

type x509UnknownAuthority struct{}

func (x509UnknownAuthority) is(err error) bool {
	return strings.Contains(err.Error(), "certificate signed by unknown authority")
}

// §13 1A acceptance test 9: at the Samba default minimum age (1 day) a change right after
// the last one is refused, deterministically, with the password unchanged.
func TestMinimumAgeRefusal(t *testing.T) {
	need(t)
	minAge(t, 1)
	defer minAge(t, 0)
	dn := newUser(t)
	s, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	last, age, err := s.(broker.AgeReporter).PasswordAge(context.Background())
	if err != nil || age != 24*time.Hour || time.Since(last) > time.Hour {
		t.Fatalf("password age: last=%v min=%v %v", last, age, err)
	}
	committed := false
	err = s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { committed = true; return nil })
	if !committed || !errors.Is(err, broker.ErrRefused) {
		t.Fatalf("change inside the minimum age: %v", err)
	}
	if _, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw)); err != nil {
		t.Fatalf("the old password stopped working after a refusal: %v", err)
	}
}

func TestChangeAndVerify(t *testing.T) {
	need(t)
	minAge(t, 0)
	dn := newUser(t)
	s, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	base, _ := s.Baseline(context.Background())
	// A failing commit sends nothing.
	if err := s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { return errors.New("no ack") }); err == nil {
		t.Fatal("change without commit")
	}
	if err := connector().Verify(context.Background(), descriptor(dn), []byte(startPw), base); err == nil {
		t.Fatal("verify passed with an unchanged pwdLastSet")
	}
	if err := s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := connector().Verify(context.Background(), descriptor(dn), []byte(otherPw), base); err != nil {
		t.Fatal(err)
	}
	if _, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw)); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("old password: %v", err)
	}
}

// rig runs the real broker state machine against a Samba account.
func rig(t *testing.T) (*brokerrig.Rig, string) {
	dn := newUser(t)
	r := brokerrig.New(t, brokerrig.Options{Connector: connector(), ConnectorType: pqcrypto.ConnectorADLDAPS, Password: startPw,
		Target: func(cp *brokertest.CP, acct, asset pqcrypto.UUID) ([]byte, pqcrypto.HexID) {
			return cp.Dep.ADTarget(t, acct, asset, dcHost, 636, dn, dc.caPEM)
		}})
	return r, dn
}

func password(t *testing.T, r *brokerrig.Rig, m *broker.Machine) []byte {
	t.Helper()
	a := r.Account(m)
	env, err := m.Trust.VerifyEnvelope(a.Run.NewEnvelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		t.Fatal(err)
	}
	dek, err := env.OpenDEK(pqcrypto.RecipientBroker, string(r.B.ID), r.B.Enc)
	if err != nil {
		t.Fatal(err)
	}
	pw, err := env.OpenPassword(dek)
	if err != nil {
		t.Fatal(err)
	}
	return pw
}

// §13 1A acceptance test 2 on AD: a rotation reaches release_authorized and the old
// password no longer authenticates.
func TestRotationOnAD(t *testing.T) {
	need(t)
	minAge(t, 0)
	r, dn := rig(t)
	m := r.Machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.Pol.AccountID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a := r.Account(m); a.Run.State != broker.StateReleaseAuthorized {
		t.Fatalf("run %+v", a.Run)
	}
	pw := password(t, r, m)
	if _, err := connector().Login(context.Background(), descriptor(dn), pw); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if _, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw)); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("old password: %v", err)
	}
}

// §13 1A acceptance test 3 on AD: killing the broker after ack_received never causes a
// second write; the outcome is the probe's.
func TestKillAfterAckOnAD(t *testing.T) {
	need(t)
	minAge(t, 0)
	for _, c := range []struct {
		point       string
		quarantined bool
	}{{"ack_received", true}, {"after_write", false}} {
		t.Run(c.point, func(t *testing.T) {
			r, dn := rig(t)
			m := r.Machine()
			m.Hook = func(p string) error {
				if p == c.point {
					return errors.New("kill")
				}
				return nil
			}
			if err := m.Rotate(context.Background(), r.Pol.AccountID, 0, time.Now()); !errors.Is(err, broker.ErrStopped) {
				t.Fatal(err)
			}
			m.J.Close()
			m2 := r.Machine()
			defer m2.J.Close()
			if err := m2.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			a := r.Account(m2)
			if a.Quarantined != c.quarantined || a.Run.State == broker.StateAborted {
				t.Fatalf("quarantined=%v state=%s", a.Quarantined, a.Run.State)
			}
			if c.quarantined {
				// No write was sent: the start password still works.
				if _, err := connector().Login(context.Background(), descriptor(dn), []byte(startPw)); err != nil {
					t.Fatalf("start password: %v", err)
				}
			} else if _, err := connector().Login(context.Background(), descriptor(dn), password(t, r, m2)); err != nil {
				t.Fatalf("new password: %v", err)
			}
		})
	}
}

// §13 1A acceptance test 9 on AD: within the default minimum age the rotation ends aborted
// (refused) with rotation_failed and the next attempt waits for the minimum age.
func TestRotationRefusedForMinimumAgeOnAD(t *testing.T) {
	need(t)
	minAge(t, 1)
	defer minAge(t, 0)
	r, _ := rig(t)
	m := r.Machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.Pol.AccountID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	a := r.Account(m)
	if a.Run.State != broker.StateAborted || a.Run.Reason != pqcrypto.ReasonRefused || a.Health != broker.HealthRotationFailed {
		t.Fatalf("run %+v health %s", a.Run, a.Health)
	}
	if a.MinAgeSeconds != 86400 || time.Until(a.MinAgeDeadline) < 23*time.Hour || !a.NextAttemptAt.Equal(a.MinAgeDeadline) {
		t.Fatalf("min age %d deadline %v next %v", a.MinAgeSeconds, a.MinAgeDeadline, a.NextAttemptAt)
	}
}
