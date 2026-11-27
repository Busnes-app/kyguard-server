// Package brokerproto is the broker listener of spec §4.1: the internal broker CA, its TLS
// configuration on both ends, pairing and the control channel.
package brokerproto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Busnes-app/ky-primitives/keyfile"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// Files of the internal broker CA in the data directory; both travel in the backup capsule
// (§9.4).
const (
	CAKeyFile  = "broker-ca.key"
	CACertFile = "broker-ca.crt"
)

const caSeedSize = mldsa.PrivateKeySize // 32 bytes; matches legacy ed25519.SeedSize

// Certificate lifetimes. The listener leaf is regenerated at every start (§9.4).
const (
	caLifetime       = 20 * 365 * 24 * time.Hour
	brokerLifetime   = 10 * 365 * 24 * time.Hour
	listenerLifetime = 365 * 24 * time.Hour
)

// ErrCAMismatch reports a CA key that does not belong to its certificate.
var ErrCAMismatch = errors.New("brokerproto: broker CA key does not match its certificate")

// CA is the internal broker CA. It authenticates the listener to brokers and brokers to the
// listener; it never authorizes work (§2).
type CA struct {
	Cert *x509.Certificate
	key  crypto.Signer
}

// SHA256 is the hex SHA-256 of the CA certificate, the value pairing tokens and brokers pin.
func (ca *CA) SHA256() pqcrypto.HexID { return CertSHA256(ca.Cert.Raw) }

// CertSHA256 is the lowercase hex SHA-256 of a DER certificate.
func CertSHA256(der []byte) pqcrypto.HexID {
	s := sha256.Sum256(der)
	return pqcrypto.HexID(hex.EncodeToString(s[:]))
}

// CreateCA makes an ML-DSA-65 CA in dir. It refuses to replace an existing key or certificate.
func CreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, CACertFile)
	if _, err := os.Stat(certPath); err == nil {
		return nil, fmt.Errorf("brokerproto: %s already exists", certPath)
	}
	seed := make([]byte, caSeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	defer clear(seed)
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "KyGuard internal broker CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(caLifetime),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, CAKeyFile)
	if err := keyfile.Store(keyPath, seed, keyfile.Hex); err != nil {
		return nil, err
	}
	if err := writeCert(certPath, der); err != nil {
		// Remove only what this call created, so init can be retried.
		os.Remove(keyPath)
		return nil, err
	}
	return LoadCA(dir)
}

// writeCert creates certPath with the PEM certificate; on failure it removes the file
// it created.
func writeCert(certPath string, der []byte) (err error) {
	f, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(certPath)
		}
	}()
	if err := pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	return f.Sync()
}

// LoadCA reads an ML-DSA-65 (or legacy Ed25519) CA from dir and checks that the key
// matches the certificate.
func LoadCA(dir string) (*CA, error) {
	seed, err := keyfile.Load(filepath.Join(dir, CAKeyFile), caSeedSize)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	raw, err := os.ReadFile(filepath.Join(dir, CACertFile))
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertPEM(raw)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, ErrCAMismatch
	}
	switch pub := cert.PublicKey.(type) {
	case *mldsa.PublicKey:
		if pub.Parameters() != mldsa.MLDSA65() {
			return nil, ErrCAMismatch
		}
		key, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
		if err != nil || !pub.Equal(key.Public()) {
			return nil, ErrCAMismatch
		}
		return &CA{Cert: cert, key: key}, nil
	case ed25519.PublicKey:
		key := ed25519.NewKeyFromSeed(seed)
		if !pub.Equal(key.Public()) {
			return nil, ErrCAMismatch
		}
		return &CA{Cert: cert, key: key}, nil
	default:
		return nil, ErrCAMismatch
	}
}

// ParseCertPEM parses exactly one PEM certificate.
func ParseCertPEM(raw []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" || strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("brokerproto: expected one PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err) // crypto/rand never fails on supported platforms
	}
	return n
}

// ListenerCert issues a fresh ML-DSA-65 leaf for the broker listener with hostname as its
// only SAN. The chain carries the CA so a pairing broker can find the certificate it
// pinned by hash.
func (ca *CA) ListenerCert(hostname string) (tls.Certificate, error) {
	if hostname == "" {
		return tls.Certificate{}, errors.New("brokerproto: KY_BROKER_HOSTNAME is required")
	}
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: hostname},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{hostname}
	}
	der, err := ca.issue(tmpl, key.Public(), listenerLifetime)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.Cert.Raw}, PrivateKey: key}, nil
}

// IssueBroker signs a broker's CSR with brokerID bound into the certificate as the URI SAN
// urn:uuid:<broker_id> (§4.1 pairing step 3). ML-DSA-65 keys (default) and legacy Ed25519
// keys are accepted.
func (ca *CA) IssueBroker(csrDER []byte, brokerID pqcrypto.UUID) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, err
	}
	var pub crypto.PublicKey
	switch k := csr.PublicKey.(type) {
	case *mldsa.PublicKey:
		if k.Parameters() != mldsa.MLDSA65() {
			return nil, errors.New("brokerproto: broker TLS key must be ML-DSA-65 or legacy Ed25519")
		}
		pub = k
	case ed25519.PublicKey:
		pub = k
	default:
		return nil, errors.New("brokerproto: broker TLS key must be ML-DSA-65 or legacy Ed25519")
	}
	if !brokerID.Valid() {
		return nil, errors.New("brokerproto: invalid broker_id")
	}
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: string(brokerID)},
		URIs:        []*url.URL{{Scheme: "urn", Opaque: "uuid:" + string(brokerID)}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, pub, brokerLifetime)
}

func (ca *CA) issue(tmpl *x509.Certificate, pub crypto.PublicKey, life time.Duration) ([]byte, error) {
	tmpl.SerialNumber = serial()
	tmpl.NotBefore = time.Now().Add(-time.Minute)
	tmpl.NotAfter = time.Now().Add(life)
	tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	return x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.key)
}

// BrokerIDOf returns the broker_id bound into a broker certificate.
func BrokerIDOf(cert *x509.Certificate) (pqcrypto.UUID, error) {
	if len(cert.URIs) != 1 || cert.URIs[0].Scheme != "urn" || !strings.HasPrefix(cert.URIs[0].Opaque, "uuid:") {
		return "", errors.New("brokerproto: certificate carries no broker_id")
	}
	id := pqcrypto.UUID(strings.TrimPrefix(cert.URIs[0].Opaque, "uuid:"))
	if !id.Valid() || cert.Subject.CommonName != string(id) {
		return "", errors.New("brokerproto: certificate carries no broker_id")
	}
	return id, nil
}
