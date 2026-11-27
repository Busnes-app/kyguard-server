package broker

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestClientCertMatchesMLDSA65AndLegacyEd25519Certs(t *testing.T) {
	k, err := CreateKeys(t.TempDir())
	if err != nil {
		t.Fatalf("CreateKeys: %v", err)
	}
	if _, ok := k.TLS.(*mldsa.PrivateKey); !ok {
		t.Fatalf("CreateKeys TLS key type = %T, want *mldsa.PrivateKey", k.TLS)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "broker"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}

	// ML-DSA-65 cert binds to k.TLS.
	mlDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.TLS.Public(), k.TLS)
	if err != nil {
		t.Fatal(err)
	}
	mlCert, err := x509.ParseCertificate(mlDER)
	if err != nil {
		t.Fatal(err)
	}
	gotML := k.ClientCert(mlCert)
	if _, ok := gotML.PrivateKey.(*mldsa.PrivateKey); !ok {
		t.Fatalf("ClientCert(ML-DSA-65) PrivateKey = %T, want *mldsa.PrivateKey", gotML.PrivateKey)
	}

	// Legacy Ed25519 cert (from pre-upgrade pairing with the same broker.key seed) binds to legacy Ed25519 key.
	edDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.legacyTLS.Public(), k.legacyTLS)
	if err != nil {
		t.Fatal(err)
	}
	edCert, err := x509.ParseCertificate(edDER)
	if err != nil {
		t.Fatal(err)
	}
	gotEd := k.ClientCert(edCert)
	if _, ok := gotEd.PrivateKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("ClientCert(legacy Ed25519) PrivateKey = %T, want ed25519.PrivateKey", gotEd.PrivateKey)
	}
}
