// Package connectortest runs connector targets in Docker for tests. Tests that need it skip
// unless KY_TEST_DOCKER is set (CI's connector job and `kslot` runs on Major set it).
// Import it from _test.go files only.
package connectortest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Enabled reports whether Docker-backed tests should run.
func Enabled() bool { return os.Getenv("KY_TEST_DOCKER") != "" }

// Docker runs one docker CLI command and returns its trimmed output.
func Docker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out)), nil
}

// Container is a running test container.
type Container struct{ Name string }

// Start builds dir as tag, creates a uniquely named container with args, copies files into
// it, and starts it.
func Start(tag, dir string, files map[string]string, args ...string) (*Container, error) {
	if _, err := Docker("build", "-q", "-t", tag, dir); err != nil {
		return nil, err
	}
	b := make([]byte, 6)
	rand.Read(b)
	c := &Container{Name: fmt.Sprintf("kyg-test-%x", b)}
	if _, err := Docker(append(append([]string{"create", "--name", c.Name}, args...), tag)...); err != nil {
		return nil, err
	}
	for src, dst := range files {
		if _, err := Docker("cp", src, c.Name+":"+dst); err != nil {
			c.Stop()
			return nil, err
		}
	}
	if _, err := Docker("start", c.Name); err != nil {
		c.Stop()
		return nil, err
	}
	return c, nil
}

// Stop removes the container.
func (c *Container) Stop() { _, _ = Docker("rm", "-f", c.Name) }

// Exec runs a command in the container.
func (c *Container) Exec(cmd ...string) (string, error) {
	return Docker(append([]string{"exec", c.Name}, cmd...)...)
}

// Port returns the 127.0.0.1 address published for a container port.
func (c *Container) Port(port string) (string, error) {
	out, err := Docker("port", c.Name, port)
	if err != nil {
		return "", err
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "127.0.0.1:") {
			return l, nil
		}
	}
	return "", fmt.Errorf("no 127.0.0.1 port in %q", out)
}

// WaitFor polls ok until it returns nil or the deadline passes.
func WaitFor(d time.Duration, ok func() error) error {
	deadline := time.Now().Add(d)
	for {
		err := ok()
		if err == nil || time.Now().After(deadline) {
			return err
		}
		time.Sleep(time.Second)
	}
}

// TLSFiles writes ca.pem, cert.pem and key.pem for a server named host into dir and returns
// the CA PEM.
func TLSFiles(dir, host string) (string, error) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kyguard test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caKey.Public(), caKey)
	if err != nil {
		return "", err
	}
	caCert, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		leaf.DNSNames, leaf.IPAddresses = nil, []net.IP{ip}
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, key.Public(), caKey)
	if err != nil {
		return "", err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))
	for name, body := range map[string][]byte{
		"ca.pem":   []byte(caPEM),
		"cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"key.pem":  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			return "", err
		}
	}
	return caPEM, nil
}
