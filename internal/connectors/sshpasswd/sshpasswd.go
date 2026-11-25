// Package sshpasswd is the ssh_passwd connector (spec §4.4): self-change of a Linux
// account's password by running passwd in a PTY over SSH.
package sshpasswd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// ErrHostKey reports a host key other than the descriptor's.
var ErrHostKey = errors.New("sshpasswd: host key does not match the descriptor")

var errOneSubmission = errors.New("sshpasswd: the credential was already submitted once")

// Connector dials only the descriptor's host and port and accepts only the host key whose
// SHA-256 the descriptor pins, checked before any authentication.
type Connector struct {
	// Dial replaces net.Dialer in tests that map the descriptor's host to a container.
	Dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	Timeout time.Duration
}

var _ broker.Connector = (*Connector)(nil)

func (c *Connector) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 30 * time.Second
}

// hostKey pins the SHA-256 of the wire-format host key.
func hostKey(pinned string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		sum := sha256.Sum256(key.Marshal())
		if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(pinned)) != 1 {
			return ErrHostKey
		}
		return nil
	}
}

func (c *Connector) dial(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte) (*ssh.Client, error) {
	if d.ConnectorType != pqcrypto.ConnectorSSHPasswd {
		return nil, errors.New("sshpasswd: not an ssh_passwd descriptor")
	}
	if len(password) == 0 {
		return nil, broker.ErrAuthFailed
	}
	pw := string(password)
	// One credential submission per login, across both methods and every interactive round:
	// a rejected password is never offered again (§4.6).
	submitted := false
	once := func() error {
		if submitted {
			return errOneSubmission
		}
		submitted = true
		return nil
	}
	cfg := &ssh.ClientConfig{
		User:            d.AuthenticatedTargetIdentity,
		HostKeyCallback: hostKey(d.Endpoint.SSHHostKeySHA256),
		Auth: []ssh.AuthMethod{
			ssh.PasswordCallback(func() (string, error) {
				if err := once(); err != nil {
					return "", err
				}
				return pw, nil
			}),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				if len(questions) == 0 {
					return nil, nil // an informational round carries no credential
				}
				for _, q := range questions {
					if !strings.Contains(strings.ToLower(q), "password") {
						return nil, errors.New("sshpasswd: unexpected keyboard-interactive question")
					}
				}
				if err := once(); err != nil {
					return nil, err
				}
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = pw
				}
				return answers, nil
			}),
		},
		Timeout: c.timeout(),
	}
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.timeout()}).DialContext
	}
	addr := net.JoinHostPort(d.Endpoint.Host, strconv.Itoa(d.Endpoint.Port))
	raw, err := dial(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	raw.SetDeadline(time.Now().Add(c.timeout()))
	cc, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		if errors.Is(err, ErrHostKey) {
			return nil, ErrHostKey
		}
		if strings.Contains(err.Error(), "unable to authenticate") || errors.Is(err, errOneSubmission) {
			return nil, broker.ErrAuthFailed
		}
		return nil, err
	}
	raw.SetDeadline(time.Time{})
	return ssh.NewClient(cc, chans, reqs), nil
}

// Login authenticates as authenticated_target_identity with password (password or
// keyboard-interactive).
func (c *Connector) Login(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte) (broker.Session, error) {
	cl, err := c.dial(ctx, d, password)
	if err != nil {
		return nil, err
	}
	return &session{c: cl, user: d.AuthenticatedTargetIdentity, timeout: c.timeout()}, nil
}

// Verify is a fresh login with the new password (§4.4).
func (c *Connector) Verify(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte, _ string) error {
	cl, err := c.dial(ctx, d, password)
	if err != nil {
		return err
	}
	return cl.Close()
}

type session struct {
	c       *ssh.Client
	user    string
	timeout time.Duration
}

// bound closes the connection if ctx ends or the timeout passes before the returned stop
// is called, so no remote command can stall the broker.
func (s *session) bound(ctx context.Context) (stop func()) {
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
		case <-ctx.Done():
			s.c.Close()
		case <-time.After(s.timeout):
			s.c.Close()
		}
	}()
	return func() { close(done) }
}

func (s *session) Close() error { return s.c.Close() }

// Baseline is the last-change date from chage -l when the account can read it, otherwise
// empty; SSH verification is the fresh login alone.
func (s *session) Baseline(ctx context.Context) (string, error) {
	last, _, err := s.chage(ctx)
	if err != nil {
		return "", nil
	}
	return "last_change=" + last.Format("2006-01-02"), nil
}

// PasswordAge reads the last change and the minimum days from chage -l (§4.4).
func (s *session) PasswordAge(ctx context.Context) (time.Time, time.Duration, error) {
	last, minDays, err := s.chage(ctx)
	return last, time.Duration(minDays) * 24 * time.Hour, err
}

func (s *session) chage(ctx context.Context) (time.Time, int, error) {
	defer s.bound(ctx)()
	ss, err := s.c.NewSession()
	if err != nil {
		return time.Time{}, 0, err
	}
	defer ss.Close()
	out, err := ss.Output("LC_ALL=C chage -l " + shellQuote(s.user))
	if err != nil {
		return time.Time{}, 0, err
	}
	var last time.Time
	minDays := -1
	for _, l := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "Last password change":
			if last, err = time.Parse("Jan 02, 2006", v); err != nil {
				return time.Time{}, 0, err
			}
		case "Minimum number of days between password change":
			if minDays, err = strconv.Atoi(v); err != nil {
				return time.Time{}, 0, err
			}
		}
	}
	if last.IsZero() || minDays < 0 {
		return time.Time{}, 0, errors.New("sshpasswd: chage -l unreadable")
	}
	return last, minDays, nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

// The linux-pam passwd prompt set; matching is on the text since the last answer.
var (
	currentPrompt = regexp.MustCompile(`(?i)(\(current\) (unix )?password|current password): *$`)
	newPrompt     = regexp.MustCompile(`(?i)(new (unix )?password|enter new (unix )?password): *$`)
	retypePrompt  = regexp.MustCompile(`(?i)(retype|re-enter|reenter) new (unix )?password: *$`)
	updated       = regexp.MustCompile(`(?i)password updated successfully|all authentication tokens updated successfully`)
)

// Change runs passwd in a PTY: it answers the current-password prompt, calls commit, then
// answers the new and retype prompts. Any prompt outside the set before the new password
// leaves is a deterministic refusal (§4.4).
func (s *session) Change(ctx context.Context, oldPassword, newPassword []byte, commit func() error) error {
	stop := s.bound(ctx) // channel setup; the prompts below carry their own deadlines
	ss, err := s.c.NewSession()
	if err != nil {
		stop()
		return err
	}
	defer ss.Close()
	err = ss.RequestPty("dumb", 24, 80, ssh.TerminalModes{ssh.ECHO: 0})
	stop()
	if err != nil {
		return err
	}
	in, err := ss.StdinPipe()
	if err != nil {
		return err
	}
	t := newTranscript()
	ss.Stdout, ss.Stderr = t, t
	// Every blocking step is bounded by ctx and the timeout: start, each write, each prompt.
	stop = s.bound(ctx)
	err = ss.Start("LC_ALL=C passwd")
	stop()
	if err != nil {
		return err
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = ss.Wait(); close(exited) }()
	answer := func(p []byte) error {
		defer s.bound(ctx)()
		_, err := in.Write(append(append([]byte(nil), p...), '\n'))
		return err
	}

	// Before the commit point every failure leaves the password unchanged.
	if k := t.await(ctx, s.timeout, exited, currentPrompt, newPrompt); k != 0 {
		return fmt.Errorf("%w: passwd did not ask for the current password: %q", broker.ErrRefused, t.tail())
	}
	if err := answer(oldPassword); err != nil {
		return err
	}
	if k := t.await(ctx, s.timeout, exited, newPrompt); k != 0 {
		return fmt.Errorf("%w: passwd did not ask for a new password: %q", broker.ErrRefused, t.tail())
	}
	if err := commit(); err != nil {
		return err
	}
	// After the commit point only a known prompt or message is deterministic.
	if err := answer(newPassword); err != nil {
		return err
	}
	switch t.await(ctx, s.timeout, exited, retypePrompt, newPrompt) {
	case 0:
	case 1: // asked again: the new password was rejected and nothing was written
		return fmt.Errorf("%w: passwd rejected the new password: %q", broker.ErrRefused, t.tail())
	default:
		return fmt.Errorf("sshpasswd: no retype prompt: %q", t.tail())
	}
	if err := answer(newPassword); err != nil {
		return err
	}
	switch t.await(ctx, s.timeout, exited, updated, newPrompt) {
	case 0:
		select {
		case <-exited:
			if waitErr == nil {
				return nil
			}
			return fmt.Errorf("sshpasswd: passwd reported success and then failed: %v", waitErr)
		case <-time.After(s.timeout):
			return errors.New("sshpasswd: passwd did not exit")
		}
	case 1: // asked again after the retype: rejected, nothing written
		return fmt.Errorf("%w: passwd rejected the new password: %q", broker.ErrRefused, t.tail())
	}
	return fmt.Errorf("sshpasswd: passwd ended unclearly: %q", t.tail())
}

// transcript collects PTY output and tracks the position of the last answer.
type transcript struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	mark int
	ch   chan struct{}
}

func newTranscript() *transcript { return &transcript{ch: make(chan struct{}, 1)} }

func (t *transcript) Write(p []byte) (int, error) {
	t.mu.Lock()
	t.buf.Write(p)
	t.mu.Unlock()
	select {
	case t.ch <- struct{}{}:
	default:
	}
	return len(p), nil
}

func (t *transcript) since() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.buf.Bytes()[t.mark:])
}

func (t *transcript) tail() string {
	b := t.since()
	if len(b) > 200 {
		b = b[len(b)-200:]
	}
	return string(b)
}

// await waits until the output since the last match ends with one of res and returns its
// index, consuming it; -1 on timeout, end of output or cancellation.
func (t *transcript) await(ctx context.Context, d time.Duration, exited <-chan struct{}, res ...*regexp.Regexp) int {
	deadline := time.After(d)
	last := false
	for {
		t.mu.Lock()
		out := bytes.TrimRight(t.buf.Bytes()[t.mark:], " \r\n")
		for i, re := range res {
			if re.Match(out) {
				t.mark = t.buf.Len()
				t.mu.Unlock()
				return i
			}
		}
		t.mu.Unlock()
		if last {
			return -1
		}
		select {
		case <-t.ch:
		case <-exited:
			last = true // one more look at what the process printed before it ended
		case <-deadline:
			return -1
		case <-ctx.Done():
			return -1
		}
	}
}

var _ io.Writer = (*transcript)(nil)
