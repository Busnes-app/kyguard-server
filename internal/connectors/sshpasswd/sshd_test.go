package sshpasswd_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/broker/brokerrig"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/connectors/connectortest"
	"github.com/Busnes-app/kyguard-server/internal/connectors/sshpasswd"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

const (
	sshHost = "db1.kyg.test"
	startPw = "Start-Passw0rd-1!"
	otherPw = "Other-Passw0rd-2!"
	sshdTag = "kyguard-test-sshd:1"
)

var target struct {
	c       *connectortest.Container
	addr    string
	hostKey string // hex SHA-256 of the wire-format host key
	err     error
}

func TestMain(m *testing.M) {
	if connectortest.Enabled() {
		target.err = startSSHD()
	}
	code := m.Run()
	if target.c != nil {
		target.c.Stop()
	}
	os.Exit(code)
}

func startSSHD() error {
	c, err := connectortest.Start(sshdTag, filepath.Join("testdata", "sshd"), nil, "-p", "127.0.0.1::22")
	if err != nil {
		return err
	}
	target.c = c
	if target.addr, err = c.Port("22/tcp"); err != nil {
		return err
	}
	pub, err := c.Exec("cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	if err != nil {
		return err
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		return err
	}
	sum := sha256.Sum256(k.Marshal())
	target.hostKey = hex.EncodeToString(sum[:])
	return connectortest.WaitFor(time.Minute, func() error {
		conn, err := net.Dial("tcp", target.addr)
		if err == nil {
			conn.Close()
		}
		return err
	})
}

func need(t *testing.T) {
	t.Helper()
	if !connectortest.Enabled() {
		t.Skip("set KY_TEST_DOCKER=1 to run against OpenSSH")
	}
	if target.err != nil {
		t.Fatalf("sshd: %v", target.err)
	}
}

func connector() *sshpasswd.Connector {
	return &sshpasswd.Connector{Timeout: 15 * time.Second, Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != net.JoinHostPort(sshHost, "22") {
			return nil, fmt.Errorf("dial outside the descriptor: %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.addr)
	}}
}

var userN int

// newUser creates an account with startPw and, optionally, a login shell.
func newUser(t *testing.T, shell string) string {
	t.Helper()
	userN++
	name := fmt.Sprintf("svc%d%d", time.Now().UnixNano()%100000, userN)
	args := []string{"useradd", "-m", name}
	if shell != "" {
		args = append(args, "-s", shell)
	}
	if _, err := target.c.Exec(args...); err != nil {
		t.Fatal(err)
	}
	if _, err := target.c.Exec("sh", "-c", "echo '"+name+":"+startPw+"' | chpasswd"); err != nil {
		t.Fatal(err)
	}
	return name
}

func descriptor(user string) *pqcrypto.TargetDescriptor {
	return &pqcrypto.TargetDescriptor{DescriptorVersion: "1", ConnectorType: pqcrypto.ConnectorSSHPasswd, AuthenticatedTargetIdentity: user,
		Endpoint: pqcrypto.Endpoint{Host: sshHost, Port: 22, SSHHostKeySHA256: target.hostKey}}
}

func logins(t *testing.T, user string) int {
	t.Helper()
	out, err := connectortest.Docker("logs", target.c.Name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(out, " "+user+" ")
}

// §13 1A acceptance test 7: a descriptor with the wrong host key fails before any
// authentication attempt, with no auth event in the target's log.
func TestWrongHostKeyFailsBeforeAuthentication(t *testing.T) {
	need(t)
	user := newUser(t, "")
	d := descriptor(user)
	d.Endpoint.SSHHostKeySHA256 = strings.Repeat("0", 64)
	if _, err := connector().Login(context.Background(), d, []byte(startPw)); !errors.Is(err, sshpasswd.ErrHostKey) {
		t.Fatalf("got %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := logins(t, user); n != 0 {
		t.Fatalf("the target logged %d authentication events for %s", n, user)
	}
	// The same user with the right key does show up, so the check above can fail.
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	time.Sleep(200 * time.Millisecond)
	if logins(t, user) == 0 {
		t.Fatal("sshd logs no authentication events at all; the check proves nothing")
	}
}

func TestLoginDeniedIsAuthFailed(t *testing.T) {
	need(t)
	user := newUser(t, "")
	if _, err := connector().Login(context.Background(), descriptor(user), []byte("wrong-Passw0rd")); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("got %v", err)
	}
}

func TestChangeAndVerify(t *testing.T) {
	need(t)
	user := newUser(t, "")
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	if err := s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { committed = true; return nil }); err != nil || !committed {
		t.Fatalf("change: %v committed=%v", err, committed)
	}
	s.Close()
	if err := connector().Verify(context.Background(), descriptor(user), []byte(otherPw), ""); err != nil {
		t.Fatal(err)
	}
	if _, err := connector().Login(context.Background(), descriptor(user), []byte(startPw)); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("old password: %v", err)
	}
}

func TestFailedCommitSendsNothing(t *testing.T) {
	need(t)
	user := newUser(t, "")
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { return errors.New("no ack") }); err == nil {
		t.Fatal("change without commit")
	}
	s.Close()
	if _, err := connector().Login(context.Background(), descriptor(user), []byte(startPw)); err != nil {
		t.Fatalf("password changed without a commit: %v", err)
	}
}

// §13 1A acceptance test 9 on SSH: an unrecognized prompt before the new password is sent
// is a deterministic refusal with the password unchanged.
func TestUnrecognizedPromptIsRefused(t *testing.T) {
	need(t)
	user := newUser(t, "/usr/local/bin/oddshell")
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	committed := false
	err = s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { committed = true; return nil })
	if !errors.Is(err, broker.ErrRefused) || committed {
		t.Fatalf("got %v committed=%v", err, committed)
	}
}

func TestMinimumAgeIsRefusedBeforeTheNewPassword(t *testing.T) {
	need(t)
	user := newUser(t, "")
	if _, err := target.c.Exec("chage", "-m", "1", "-d", time.Now().UTC().Format("2006-01-02"), user); err != nil {
		t.Fatal(err)
	}
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if last, age, err := s.(broker.AgeReporter).PasswordAge(context.Background()); err != nil || age != 24*time.Hour || time.Since(last) > 48*time.Hour {
		t.Fatalf("password age: %v %v %v", last, age, err)
	}
	committed := false
	err = s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error { committed = true; return nil })
	if !errors.Is(err, broker.ErrRefused) || committed {
		t.Fatalf("got %v committed=%v", err, committed)
	}
}

func rig(t *testing.T) (*brokerrig.Rig, string) {
	user := newUser(t, "")
	r := brokerrig.New(t, brokerrig.Options{Connector: connector(), ConnectorType: pqcrypto.ConnectorSSHPasswd, Password: startPw,
		Target: func(cp *brokertest.CP, acct, asset pqcrypto.UUID) ([]byte, pqcrypto.HexID) {
			return cp.Dep.SSHTarget(t, acct, asset, sshHost, 22, user, pqcrypto.HexID(target.hostKey))
		}})
	return r, user
}

func newPassword(t *testing.T, r *brokerrig.Rig, m *broker.Machine) []byte {
	t.Helper()
	env, err := m.Trust.VerifyEnvelope(r.Account(m).Run.NewEnvelope, pqcrypto.EnvelopeContext{})
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

// §13 1A acceptance test 2 on SSH.
func TestRotationOnSSH(t *testing.T) {
	need(t)
	r, user := rig(t)
	m := r.Machine()
	defer m.J.Close()
	if err := m.Rotate(context.Background(), r.Pol.AccountID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	if a := r.Account(m); a.Run.State != broker.StateReleaseAuthorized {
		t.Fatalf("run %+v", a.Run)
	}
	if err := connector().Verify(context.Background(), descriptor(user), newPassword(t, r, m), ""); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if _, err := connector().Login(context.Background(), descriptor(user), []byte(startPw)); !errors.Is(err, broker.ErrAuthFailed) {
		t.Fatalf("old password: %v", err)
	}
}

// §13 1A acceptance test 3 on SSH.
func TestKillAfterAckOnSSH(t *testing.T) {
	need(t)
	for _, c := range []struct {
		point       string
		quarantined bool
	}{{"ack_received", true}, {"after_write", false}} {
		t.Run(c.point, func(t *testing.T) {
			r, user := rig(t)
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
			pw := []byte(startPw)
			if !c.quarantined {
				pw = newPassword(t, r, m2)
			}
			if err := connector().Verify(context.Background(), descriptor(user), pw, ""); err != nil {
				t.Fatalf("password after recovery: %v", err)
			}
		})
	}
}

// A new password linux-pam rejects (here: the same as the old one) is re-prompted, never
// written: a deterministic refusal after the commit point.
func TestRejectedNewPasswordIsRefused(t *testing.T) {
	need(t)
	user := newUser(t, "")
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	committed := false
	err = s.Change(context.Background(), []byte(startPw), []byte(startPw), func() error { committed = true; return nil })
	if !errors.Is(err, broker.ErrRefused) || !committed {
		t.Fatalf("got %v committed=%v", err, committed)
	}
	if _, err := connector().Login(context.Background(), descriptor(user), []byte(startPw)); err != nil {
		t.Fatalf("password after the refusal: %v", err)
	}
}

// No byte of the new password leaves before commit returns: when commit runs, the target
// has received the current password and nothing else.
func TestNothingNewLeavesBeforeTheCommit(t *testing.T) {
	need(t)
	user := newUser(t, "/usr/local/bin/recordshell")
	s, err := connector().Login(context.Background(), descriptor(user), []byte(startPw))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	seen := ""
	s.Change(context.Background(), []byte(startPw), []byte(otherPw), func() error {
		time.Sleep(300 * time.Millisecond) // let anything already sent land
		seen, _ = target.c.Exec("cat", "/tmp/answers-"+user)
		return nil
	})
	if seen != "current" {
		t.Fatalf("at the commit point the target had received %q", seen)
	}
}
