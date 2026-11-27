// Package broker is kyguard-broker (spec §4): its key files, journal, pairing and the
// daemon that holds the control channel.
package broker

import (
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// KeyFile holds the broker's four private seeds, 0600, written with ky-primitives/keyfile
// (§4.1): TLS (ML-DSA-65; legacy pairings used Ed25519 from the same 32-byte seed),
// signing (ML-DSA-65 and Ed25519) and encryption (X-Wing).
const KeyFile = "broker.key"

const seedLen = 32

// Keys are the broker's private keys. They never leave the host.
type Keys struct {
	TLS       crypto.Signer
	legacyTLS ed25519.PrivateKey
	Sig       *pqcrypto.SigningKey
	Enc       recoverykey.PrivateKey
}

// CreateKeys generates fresh keys in dir. It never replaces an existing key file.
func CreateKeys(dir string) (*Keys, error) {
	path := filepath.Join(dir, KeyFile)
	if _, err := os.Stat(path); err == nil {
		return nil, fmt.Errorf("broker: %s already exists; this host is already paired", path)
	}
	seeds := make([]byte, 4*seedLen)
	if _, err := rand.Read(seeds); err != nil {
		return nil, err
	}
	defer clear(seeds)
	if err := keyfile.Store(path, seeds, keyfile.Hex); err != nil {
		return nil, err
	}
	return LoadKeys(dir)
}

// LoadKeys opens the key file, refusing one readable by anyone but its owner.
func LoadKeys(dir string) (*Keys, error) {
	path := filepath.Join(dir, KeyFile)
	if err := keyfile.RequireOwnerOnly(path); err != nil {
		return nil, err
	}
	seeds, err := keyfile.Load(path, 4*seedLen)
	if err != nil {
		return nil, err
	}
	defer clear(seeds)
	return openKeys(seeds)
}

// openKeys rebuilds the keys from their seeds; the broker's own X-Wing key is how it
// unwraps DEKs sealed to it (§3.5).
func openKeys(seeds []byte) (*Keys, error) {
	if len(seeds) != 4*seedLen {
		return nil, errors.New("broker: key file has the wrong length")
	}
	tlsKey, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), seeds[:seedLen])
	if err != nil {
		return nil, err
	}
	sig, err := pqcrypto.NewSigningKey(seeds[seedLen:2*seedLen], seeds[2*seedLen:3*seedLen])
	if err != nil {
		return nil, err
	}
	enc, err := recoverykey.FromSeed(seeds[3*seedLen:])
	if err != nil {
		return nil, err
	}
	return &Keys{
		TLS:       tlsKey,
		legacyTLS: ed25519.NewKeyFromSeed(seeds[:seedLen]),
		Sig:       sig,
		Enc:       enc,
	}, nil
}

// SigKeyID and EncKeyID are what `kyguard-broker pair` prints for the Custodian check.
func (k *Keys) SigKeyID() pqcrypto.HexID {
	id, err := k.Sig.Public().SigKeyID()
	if err != nil {
		panic(err) // a key built by NewSigningKey always has a valid public half
	}
	return id
}

// EncKeyID is the enc_key_id of the broker's X-Wing key.
func (k *Keys) EncKeyID() pqcrypto.HexID { return pqcrypto.HexID(k.Enc.Public().ID()) }

// ClientCert pairs the broker certificate with its matching TLS key (ML-DSA-65 for new
// pairings, or legacy Ed25519 for hosts paired before the ML-DSA-65 migration).
func (k *Keys) ClientCert(cert *x509.Certificate) tls.Certificate {
	var priv crypto.Signer = k.TLS
	if cert != nil {
		if _, isEd := cert.PublicKey.(ed25519.PublicKey); isEd && len(k.legacyTLS) == ed25519.PrivateKeySize {
			priv = k.legacyTLS
		}
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: priv, Leaf: cert}
}

// Version is the broker version announced on the channel.
const Version = brokerproto.BrokerVersion
