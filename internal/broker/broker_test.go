package broker_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto/brokertest"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
)

func newApp(t *testing.T) (*broker.App, *bytes.Buffer) {
	out := &bytes.Buffer{}
	return &broker.App{Dir: filepath.Join(t.TempDir(), "broker"), Out: out, Nudges: make(chan struct{}, 1)}, out
}

// member is how Custodians list the paired broker, from what pair printed.
func member(t *testing.T, a *broker.App, status string) pqcrypto.BrokerMember {
	t.Helper()
	j, err := broker.OpenJournal(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	id, err := j.Identity()
	if err != nil {
		t.Fatal(err)
	}
	k, err := broker.LoadKeys(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	b := &pqtest.Broker{ID: id.BrokerID, Sig: k.Sig, Enc: k.Enc, CertSHA256: brokerproto.CertSHA256(id.Cert.Raw)}
	return b.Member(status)
}

func TestPairPrintsTheIdentityForTheCustodianCheck(t *testing.T) {
	cp := brokertest.NewCP(t)
	a, out := newApp(t)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), string(cp.Dep.Fingerprint), ""); err != nil {
		t.Fatal(err)
	}
	m := member(t, a, pqcrypto.StatusActive)
	sid, _ := m.SigPub.SigKeyID()
	eid, _ := pqcrypto.EncKeyID(m.EncPub)
	for _, want := range []string{string(m.BrokerID), string(sid), string(eid), string(m.MTLSCertSHA256)} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("pair output lacks %s:\n%s", want, out)
		}
	}
	for _, f := range []string{broker.KeyFile, broker.JournalFile} {
		fi, err := os.Stat(filepath.Join(a.Dir, f))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, fi.Mode(), err)
		}
	}
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), string(cp.Dep.Fingerprint), ""); err == nil {
		t.Fatal("paired twice")
	}
}

func TestPairWithTheBundleFile(t *testing.T) {
	cp := brokertest.NewCP(t)
	a, _ := newApp(t)
	wrong := filepath.Join(t.TempDir(), "wrong.json")
	os.WriteFile(wrong, pqtest.New(t).Bundle, 0o600)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), "", wrong); err == nil {
		t.Fatal("paired against another deployment's bundle")
	}
	k1, err := broker.LoadKeys(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	right := filepath.Join(t.TempDir(), "bundle.json")
	os.WriteFile(right, cp.Dep.Bundle, 0o600)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), "", right); err != nil {
		t.Fatal(err)
	}
	k2, _ := broker.LoadKeys(a.Dir)
	if k1.SigKeyID() != k2.SigKeyID() {
		t.Fatal("an unpaired key file was replaced")
	}
	if err := a.Pair(context.Background(), "", string(cp.Dep.Fingerprint), right); err == nil {
		t.Fatal("both --bootstrap-fingerprint and --bootstrap-bundle accepted")
	}
}

func TestRunHoldsTheChannel(t *testing.T) {
	cp := brokertest.NewCP(t)
	a, _ := newApp(t)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), string(cp.Dep.Fingerprint), ""); err != nil {
		t.Fatal(err)
	}
	m := member(t, a, pqcrypto.StatusActive)
	cp.AdmitPool(1, m)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for cp.L.Send(context.Background(), m.BrokerID, brokerproto.Message{V: 1, Type: brokerproto.MsgNudge}) != nil {
		if time.Now().After(deadline) {
			t.Fatal("broker never connected")
		}
		time.Sleep(20 * time.Millisecond)
	}
	// A second daemon on the same journal is refused while the first holds the lock.
	if _, err := broker.OpenJournal(a.Dir); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("second journal open: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestLoadKeysRefusesAKeyFileOthersCanRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := broker.CreateKeys(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := broker.CreateKeys(dir); err == nil {
		t.Fatal("CreateKeys replaced a key file")
	}
	os.Chmod(filepath.Join(dir, broker.KeyFile), 0o644)
	if _, err := broker.LoadKeys(dir); err == nil {
		t.Fatal("loaded a world-readable key file")
	}
}

func TestRunRefusesAnUnpairedHost(t *testing.T) {
	a, _ := newApp(t)
	os.MkdirAll(a.Dir, 0o700)
	if err := a.Run(context.Background()); err != broker.ErrNotPaired {
		t.Fatalf("got %v", err)
	}
}

// A dropped channel never lets a second Machine work on the journal while the first is
// still inside a rotation: the daemon reconnects only once that rotation has ended
// (security review of #12).
func TestReconnectWaitsForTheRotationInFlight(t *testing.T) {
	cp := brokertest.NewCP(t)
	a, _ := newApp(t)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), string(cp.Dep.Fingerprint), ""); err != nil {
		t.Fatal(err)
	}
	j, err := broker.OpenJournal(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := j.Identity()
	j.Close()
	k, err := broker.LoadKeys(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	b := &brokertest.Broker{ID: id.BrokerID, TLS: k.TLS, Sig: k.Sig, Enc: k.Enc, Paired: &brokerproto.Paired{BrokerID: id.BrokerID, Cert: id.Cert, CACert: id.CACert}}
	cp.AdmitPool(1, b.Member(pqcrypto.StatusActive))
	r := &rig{t: t, cp: cp, b: b, dir: a.Dir, target: newTarget(initialPassword)}
	r.pol = cp.Account(func(p *pqcrypto.PolicyManifest) {
		p.RotationSchedule = &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(time.Now().Add(-time.Hour)), IntervalSeconds: 1}
	})
	r.seed()
	r.target.hold, r.target.held = make(chan struct{}), make(chan struct{}, 1)
	a.Connectors = map[string]broker.Connector{pqcrypto.ConnectorSSHPasswd: r.target}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- a.Run(ctx) }()
	deadline := time.Now().Add(15 * time.Second)
	for waiting := true; waiting; {
		select {
		case <-r.target.held:
			waiting = false
		case <-time.After(100 * time.Millisecond):
			if time.Now().After(deadline) {
				t.Fatal("no rotation reached the target")
			}
			cp.L.Send(context.Background(), b.ID, brokerproto.Message{V: 1, Type: brokerproto.MsgNudge})
		}
	}
	// Drop the daemon's channel: the listener replaces it with this connection.
	if err := cp.Dial(b); err != nil {
		t.Fatal(err)
	}
	// The daemon's backoff is one second; a reconnect would replace this connection.
	time.Sleep(2500 * time.Millisecond)
	cctx, ccancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ccancel()
	var s brokerproto.SyncReply
	if err := b.Conn.Call(cctx, brokerproto.MsgSync, brokerproto.SyncRequest{}, &s); err != nil {
		t.Fatalf("the daemon reconnected while its rotation was still running: %v", err)
	}
	close(r.target.hold)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The identity outlives the journal transaction that read it: a reconnect after the journal
// grew (and bbolt remapped it) dials with the same certificates.
func TestIdentityOutlivesTheJournalMapping(t *testing.T) {
	cp := brokertest.NewCP(t)
	a, _ := newApp(t)
	if err := a.Pair(context.Background(), cp.Token(cp.Srv, time.Minute), string(cp.Dep.Fingerprint), ""); err != nil {
		t.Fatal(err)
	}
	j, err := broker.OpenJournal(a.Dir)
	if err != nil {
		t.Fatal(err)
	}
	id, err := j.Identity()
	if err != nil {
		t.Fatal(err)
	}
	want := brokerproto.CertSHA256(bytes.Clone(id.Cert.Raw)) + brokerproto.CertSHA256(bytes.Clone(id.CACert.Raw))
	j.Close() // unmaps the file
	if got := brokerproto.CertSHA256(id.Cert.Raw) + brokerproto.CertSHA256(id.CACert.Raw); got != want {
		t.Fatal("identity certificates changed after the journal closed")
	}
}
