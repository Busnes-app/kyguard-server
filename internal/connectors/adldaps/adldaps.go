// Package adldaps is the ad_ldaps connector (spec §4.4): self-change of an Active Directory
// account's password over LDAPS from the Linux broker. No StartTLS, no plain LDAP, no NTLM,
// no Kerberos.
package adldaps

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
	"unicode/utf16"

	"github.com/go-ldap/ldap/v3"

	"github.com/Busnes-app/kyguard-server/internal/broker"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// Connector dials only the verified descriptor's host and port and trusts only its
// tls_ca_pem, with the host as the TLS server name.
type Connector struct {
	// Dial replaces net.Dialer in tests that map the descriptor's host to a container. The
	// TLS server name is the descriptor's host either way.
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

// open dials ldaps://host:port from the descriptor and completes the TLS handshake against
// the pinned CA and hostname. It also returns the raw connection, which watch closes when
// an operation's context ends.
func (c *Connector) open(ctx context.Context, d *pqcrypto.TargetDescriptor) (*ldap.Conn, net.Conn, error) {
	if d.ConnectorType != pqcrypto.ConnectorADLDAPS {
		return nil, nil, errors.New("adldaps: not an ad_ldaps descriptor")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(d.Endpoint.TLSCAPEM)) {
		return nil, nil, errors.New("adldaps: descriptor tls_ca_pem holds no certificate")
	}
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: c.timeout()}).DialContext
	}
	raw, err := dial(ctx, "tcp", net.JoinHostPort(d.Endpoint.Host, strconv.Itoa(d.Endpoint.Port)))
	if err != nil {
		return nil, nil, err
	}
	tc := tls.Client(raw, &tls.Config{RootCAs: roots, ServerName: d.Endpoint.Host, MinVersion: tls.VersionTLS12})
	hctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()
	if err := tc.HandshakeContext(hctx); err != nil {
		raw.Close()
		return nil, nil, err
	}
	l := ldap.NewConn(tc, true)
	l.SetTimeout(c.timeout())
	l.Start()
	return l, raw, nil
}

// watch closes raw if ctx ends before the returned stop is called: go-ldap requests observe
// only the fixed timeout, so cancellation must end them by closing the connection.
func watch(ctx context.Context, raw net.Conn) (stop func() bool) {
	return context.AfterFunc(ctx, func() { raw.Close() })
}

// bind is a simple bind; LDAP invalidCredentials (49, including AD 52e) is deterministic.
func bind(l *ldap.Conn, dn string, password []byte) error {
	if len(password) == 0 {
		return broker.ErrAuthFailed // never an unauthenticated bind
	}
	err := l.Bind(dn, string(password))
	if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
		return broker.ErrAuthFailed
	}
	return err
}

// Login binds as authenticated_target_identity.
func (c *Connector) Login(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte) (broker.Session, error) {
	l, raw, err := c.open(ctx, d)
	if err != nil {
		return nil, err
	}
	stop := watch(ctx, raw)
	err = bind(l, d.AuthenticatedTargetIdentity, password)
	stop()
	if err != nil {
		l.Close()
		return nil, err
	}
	return &session{l: l, raw: raw, dn: d.AuthenticatedTargetIdentity}, nil
}

// Verify binds again with the new password on the same host and checks that pwdLastSet
// advanced past the baseline (§4.4).
func (c *Connector) Verify(ctx context.Context, d *pqcrypto.TargetDescriptor, password []byte, baseline string) error {
	s, err := c.Login(ctx, d, password)
	if err != nil {
		return err
	}
	defer s.Close()
	before, _, err := parseBaseline(baseline)
	if err != nil {
		return err
	}
	now, _, err := s.(*session).read(ctx)
	if err != nil {
		return err
	}
	if now <= before {
		return errors.New("adldaps: pwdLastSet did not advance")
	}
	return nil
}

type session struct {
	l   *ldap.Conn
	raw net.Conn
	dn  string
}

// read returns pwdLastSet and msDS-KeyVersionNumber of the account's own object.
func (s *session) read(ctx context.Context) (pwdLastSet, kvno int64, err error) {
	defer watch(ctx, s.raw)()
	res, err := s.l.Search(ldap.NewSearchRequest(s.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 30, false,
		"(objectClass=*)", []string{"pwdLastSet", "msDS-KeyVersionNumber"}, nil))
	if err != nil {
		return 0, 0, err
	}
	if len(res.Entries) != 1 {
		return 0, 0, errors.New("adldaps: account object not found")
	}
	e := res.Entries[0]
	if pwdLastSet, err = strconv.ParseInt(e.GetAttributeValue("pwdLastSet"), 10, 64); err != nil {
		return 0, 0, fmt.Errorf("adldaps: pwdLastSet: %w", err)
	}
	kvno, _ = strconv.ParseInt(e.GetAttributeValue("msDS-KeyVersionNumber"), 10, 64)
	return pwdLastSet, kvno, nil
}

func parseBaseline(b string) (pwdLastSet, kvno int64, err error) {
	if _, err := fmt.Sscanf(b, "pwdLastSet=%d kvno=%d", &pwdLastSet, &kvno); err != nil {
		return 0, 0, errors.New("adldaps: malformed baseline")
	}
	return pwdLastSet, kvno, nil
}

func (s *session) Baseline(ctx context.Context) (string, error) {
	p, k, err := s.read(ctx)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pwdLastSet=%d kvno=%d", p, k), nil
}

// Change sends one modify on unicodePwd: delete the old value and add the new one, each the
// UTF-16LE encoding of the double-quoted password.
func (s *session) Change(ctx context.Context, oldPassword, newPassword []byte, commit func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := commit(); err != nil {
		return err
	}
	defer watch(ctx, s.raw)()
	if err := ctx.Err(); err != nil {
		return err // committed, but no modify starts after cancellation
	}
	oldV, newV := unicodePwd(oldPassword), unicodePwd(newPassword)
	defer clear(oldV)
	defer clear(newV)
	req := ldap.NewModifyRequest(s.dn, nil)
	req.Delete("unicodePwd", []string{string(oldV)})
	req.Add("unicodePwd", []string{string(newV)})
	err := s.l.Modify(req)
	// Constraint violation (password policy, history, minimum age) and unwilling to
	// perform leave the password unchanged.
	if ldap.IsErrorWithCode(err, ldap.LDAPResultConstraintViolation) || ldap.IsErrorWithCode(err, ldap.LDAPResultUnwillingToPerform) {
		return fmt.Errorf("%w: %v", broker.ErrRefused, err)
	}
	return err
}

func (s *session) Close() error { return s.l.Close() }

// PasswordAge reports the account's last change and the domain's minPwdAge (§4.4).
func (s *session) PasswordAge(ctx context.Context) (time.Time, time.Duration, error) {
	defer watch(ctx, s.raw)()
	last, _, err := s.read(ctx)
	if err != nil {
		return time.Time{}, 0, err
	}
	root, err := s.l.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 30, false,
		"(objectClass=*)", []string{"defaultNamingContext"}, nil))
	if err != nil || len(root.Entries) != 1 {
		return time.Time{}, 0, errors.New("adldaps: no rootDSE")
	}
	dom, err := s.l.Search(ldap.NewSearchRequest(root.Entries[0].GetAttributeValue("defaultNamingContext"), ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, 30, false, "(objectClass=*)", []string{"minPwdAge"}, nil))
	if err != nil || len(dom.Entries) != 1 {
		return time.Time{}, 0, errors.New("adldaps: no domain object")
	}
	min, err := strconv.ParseInt(dom.Entries[0].GetAttributeValue("minPwdAge"), 10, 64)
	if err != nil {
		return time.Time{}, 0, errors.New("adldaps: minPwdAge")
	}
	// minPwdAge is a negative count of 100 ns intervals; pwdLastSet a FILETIME.
	return FileTime(last), time.Duration(-min) * 100, nil
}

// FileTime converts a Windows FILETIME (100 ns intervals since 1601-01-01 UTC).
func FileTime(ft int64) time.Time {
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns
	return time.Unix(0, (ft-epochDiff)*100).UTC()
}

// unicodePwd is UTF-16LE of the password in double quotes. The caller wipes it.
func unicodePwd(password []byte) []byte {
	units := utf16.Encode([]rune("\"" + string(password) + "\""))
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	clear(units)
	return out
}
