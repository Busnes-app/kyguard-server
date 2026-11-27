package brokerproto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/coder/websocket"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Paired is what a broker keeps from a successful pairing.
type Paired struct {
	BrokerID pqcrypto.UUID
	Cert     *x509.Certificate
	CACert   *x509.Certificate
	Bundle   []byte // canonical, verified against the operator's fingerprint
	Trust    *pqcrypto.Trust
}

// Pair is the broker side of §4.1 pairing steps 2 and 3. It pins the CA hash from the token
// and the listener hostname from its URL, sends the CSR and public keys, then checks the
// returned certificate and verifies the bundle against the fingerprint the operator typed.
func Pair(ctx context.Context, tok *Token, fingerprint pqcrypto.HexID, tlsKey crypto.Signer, sigPub pqcrypto.HybridPub, encPub []byte) (*Paired, error) {
	u, err := url.Parse(tok.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return nil, ErrToken
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "kyguard-broker"}}, tlsKey)
	if err != nil {
		return nil, err
	}
	body, err := canonical.Marshal(PairRequest{Secret: tok.Secret, CSR: csr, SigPub: sigPub, EncPub: encPub, Version: BrokerVersion})
	if err != nil {
		return nil, err
	}
	hc := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: ClientTLS(tok.CASHA256, u.Hostname(), nil)}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tok.URL+PathPair, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("brokerproto: pairing refused: %s %s", resp.Status, bytes.TrimSpace(raw))
	}
	var pr PairResponse
	if _, err := canonical.Decode(raw, &pr); err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(pr.CACert)
	if err != nil || CertSHA256(ca.Raw) != tok.CASHA256 {
		return nil, ErrPinnedCA
	}
	cert, err := x509.ParseCertificate(pr.Cert)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return nil, err
	}
	if id, err := BrokerIDOf(cert); err != nil || id != pr.BrokerID {
		return nil, errors.New("brokerproto: certificate does not carry the assigned broker_id")
	}
	tr, err := pqcrypto.NewTrust(pr.Bundle, fingerprint)
	if err != nil {
		return nil, fmt.Errorf("brokerproto: bundle does not verify against the bootstrap fingerprint: %w", err)
	}
	return &Paired{BrokerID: pr.BrokerID, Cert: cert, CACert: ca, Bundle: pr.Bundle, Trust: tr}, nil
}

// Dial opens the control channel with the broker's client certificate, pinning the CA it
// stored at pairing and the listener hostname.
func Dial(ctx context.Context, listenerURL string, ca *x509.Certificate, client tls.Certificate) (*websocket.Conn, error) {
	u, err := url.Parse(listenerURL)
	if err != nil || u.Scheme != "https" {
		return nil, ErrToken
	}
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: ClientTLS(CertSHA256(ca.Raw), u.Hostname(), &client)}}
	c, resp, err := websocket.Dial(ctx, "wss://"+u.Host+PathChannel, &websocket.DialOptions{
		HTTPClient: hc,
		HTTPHeader: http.Header{VersionHeader: {BrokerVersion}},
	})
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("brokerproto: channel refused: %s", resp.Status)
		}
		return nil, err
	}
	c.SetReadLimit(MaxFrame)
	return c, nil
}
