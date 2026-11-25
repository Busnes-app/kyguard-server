package brokerproto

import (
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// curves puts the hybrid post-quantum key exchange first (§4.1, §11).
var curves = []tls.CurveID{tls.X25519MLKEM768, tls.X25519}

// ServerTLS is the listener configuration of §4.1. Client certificates are optional at the
// TLS layer (pairing has none) and verified against the CA when present; the channel
// handler refuses a connection without one.
func ServerTLS(ca *CA, leaf tls.Certificate) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		ClientAuth:       tls.VerifyClientCertIfGiven,
		ClientCAs:        pool,
		CurvePreferences: curves,
		Certificates:     []tls.Certificate{leaf},
	}
}

// ErrPinnedCA reports a listener whose chain does not lead to the pinned CA.
var ErrPinnedCA = errors.New("brokerproto: listener certificate does not chain to the pinned CA")

// ClientTLS is the broker's configuration: the listener must present a leaf for hostname
// issued by the CA whose SHA-256 is pinned. During pairing the broker knows only that hash,
// so the CA certificate is taken from the presented chain and accepted only if it hashes to
// the pin; Go's default verification is replaced, not skipped, by VerifyConnection.
func ClientTLS(caSHA256 pqcrypto.HexID, hostname string, client *tls.Certificate) *tls.Config {
	// pinVerified: InsecureSkipVerify only turns off the system-root chain check, which
	// VerifyConnection replaces with verifyListener (chain to the pinned CA, hostname,
	// serverAuth). Every handshake runs it; TestClientTLSPinsTheCA and
	// TestBrokerRefusesAnotherCA fail if it is weakened.
	pinVerified := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   curves,
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyConnection
		VerifyConnection: func(cs tls.ConnectionState) error {
			return verifyListener(cs.PeerCertificates, caSHA256, hostname)
		},
	}
	if client != nil {
		pinVerified.Certificates = []tls.Certificate{*client}
	}
	return pinVerified
}

func verifyListener(chain []*x509.Certificate, pin pqcrypto.HexID, hostname string) error {
	if len(chain) < 2 || hostname == "" || !pin.Valid() {
		return ErrPinnedCA
	}
	var ca *x509.Certificate
	for _, c := range chain[1:] {
		if subtle.ConstantTimeCompare([]byte(CertSHA256(c.Raw)), []byte(pin)) == 1 {
			ca = c
		}
	}
	if ca == nil {
		return ErrPinnedCA
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	_, err := chain[0].Verify(x509.VerifyOptions{DNSName: hostname, Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}
