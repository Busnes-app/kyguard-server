package brokerproto_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/keyfile"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

func TestCreateCAUsesMLDSA65AndIssuesMLDSA65ListenerLeaf(t *testing.T) {
	ca, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	pub, ok := ca.Cert.PublicKey.(*mldsa.PublicKey)
	if !ok {
		t.Fatalf("CA public key type = %T, want *mldsa.PublicKey", ca.Cert.PublicKey)
	}
	if pub.Parameters() != mldsa.MLDSA65() {
		t.Fatalf("CA ML-DSA params = %v, want ML-DSA-65", pub.Parameters())
	}

	leaf, err := ca.ListenerCert("127.0.0.1")
	if err != nil {
		t.Fatalf("ListenerCert: %v", err)
	}
	parsedLeaf, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse listener leaf: %v", err)
	}
	leafPub, ok := parsedLeaf.PublicKey.(*mldsa.PublicKey)
	if !ok || leafPub.Parameters() != mldsa.MLDSA65() {
		t.Fatalf("listener leaf public key = %T, want ML-DSA-65", parsedLeaf.PublicKey)
	}
}

func TestIssueBrokerAcceptsMLDSA65AndLegacyEd25519AndRejectsOtherKeys(t *testing.T) {
	ca, err := brokerproto.CreateCA(t.TempDir())
	if err != nil {
		t.Fatalf("CreateCA: %v", err)
	}
	id := pqcrypto.UUID("01960000-0000-7000-8000-000000000001")

	// ML-DSA-65 CSR succeeds.
	ml65, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("generate ML-DSA-65 key: %v", err)
	}
	ml65CSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, ml65)
	if err != nil {
		t.Fatalf("create ML-DSA-65 CSR: %v", err)
	}
	der, err := ca.IssueBroker(ml65CSR, id)
	if err != nil {
		t.Fatalf("IssueBroker(ML-DSA-65): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ML-DSA-65 cert: %v", err)
	}
	if pub, ok := cert.PublicKey.(*mldsa.PublicKey); !ok || pub.Parameters() != mldsa.MLDSA65() {
		t.Fatalf("issued broker cert key = %T, want ML-DSA-65", cert.PublicKey)
	}

	// Legacy Ed25519 CSR still succeeds for rolling upgrades.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	edCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, edKey)
	if err != nil {
		t.Fatalf("create Ed25519 CSR: %v", err)
	}
	if _, err := ca.IssueBroker(edCSR, id); err != nil {
		t.Fatalf("IssueBroker(legacy Ed25519): %v", err)
	}

	// ML-DSA-44 CSR is rejected (below NIST Category 3).
	ml44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("generate ML-DSA-44 key: %v", err)
	}
	ml44CSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, ml44)
	if err != nil {
		t.Fatalf("create ML-DSA-44 CSR: %v", err)
	}
	if _, err := ca.IssueBroker(ml44CSR, id); err == nil {
		t.Fatal("IssueBroker accepted ML-DSA-44 CSR, want error")
	}

	// ECDSA P-256 CSR is rejected.
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	ecCSR, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, ecKey)
	if err != nil {
		t.Fatalf("create ECDSA CSR: %v", err)
	}
	if _, err := ca.IssueBroker(ecCSR, id); err == nil {
		t.Fatal("IssueBroker accepted ECDSA P-256 CSR, want error")
	}
}

func TestLoadCASupportsLegacyEd25519CAAndFullMLDSA65Handshake(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	edKey := ed25519.NewKeyFromSeed(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Legacy KyGuard CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, edKey.Public(), edKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := keyfile.Store(filepath.Join(dir, brokerproto.CAKeyFile), seed, keyfile.Hex); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, brokerproto.CACertFile), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}

	ca, err := brokerproto.LoadCA(dir)
	if err != nil {
		t.Fatalf("LoadCA(legacy Ed25519): %v", err)
	}
	if _, ok := ca.Cert.PublicKey.(ed25519.PublicKey); !ok {
		t.Fatalf("legacy CA key type = %T, want ed25519.PublicKey", ca.Cert.PublicKey)
	}

	// Legacy Ed25519 CA can issue ML-DSA-65 listener & broker certs and complete X25519MLKEM768 mTLS.
	leaf, err := ca.ListenerCert("127.0.0.1")
	if err != nil {
		t.Fatalf("legacy CA ListenerCert: %v", err)
	}
	brokerKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "broker"}}, brokerKey)
	if err != nil {
		t.Fatal(err)
	}
	brokerDER, err := ca.IssueBroker(csr, pqcrypto.UUID("01960000-0000-7000-8000-000000000001"))
	if err != nil {
		t.Fatalf("legacy CA IssueBroker(ML-DSA-65): %v", err)
	}
	brokerCert, err := x509.ParseCertificate(brokerDER)
	if err != nil {
		t.Fatal(err)
	}
	clientTLS := brokerproto.ClientTLS(ca.SHA256(), "127.0.0.1", &tls.Certificate{
		Certificate: [][]byte{brokerDER},
		PrivateKey:  brokerKey,
		Leaf:        brokerCert,
	})
	serverTLS := brokerproto.ServerTLS(ca, leaf)

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		defer conn.Close()
		tc := conn.(*tls.Conn)
		if err := tc.Handshake(); err != nil {
			srvErr <- err
			return
		}
		if len(tc.ConnectionState().PeerCertificates) == 0 {
			srvErr <- errors.New("missing client certificate")
			return
		}
		srvErr <- nil
	}()

	conn, err := tls.Dial("tcp", ln.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial with ML-DSA-65 leaf+client under legacy Ed25519 CA: %v", err)
	}
	if conn.ConnectionState().CurveID != tls.X25519MLKEM768 {
		t.Fatalf("CurveID = %v, want X25519MLKEM768", conn.ConnectionState().CurveID)
	}
	_ = conn.Close()
	if err := <-srvErr; err != nil {
		t.Fatalf("server handshake: %v", err)
	}

	// Corrupted seed still fails LoadCA with ErrCAMismatch.
	wrongSeed := make([]byte, ed25519.SeedSize)
	wrongSeed[0] = seed[0] ^ 0xff
	_ = os.Remove(filepath.Join(dir, brokerproto.CAKeyFile))
	if err := keyfile.Store(filepath.Join(dir, brokerproto.CAKeyFile), wrongSeed, keyfile.Hex); err != nil {
		t.Fatal(err)
	}
	if _, err := brokerproto.LoadCA(dir); !errors.Is(err, brokerproto.ErrCAMismatch) {
		t.Fatalf("LoadCA with wrong seed = %v, want ErrCAMismatch", err)
	}
}
