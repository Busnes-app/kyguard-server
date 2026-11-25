package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/Busnes-app/ky-primitives/keyfile"
	"github.com/Busnes-app/ky-primitives/password"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"golang.org/x/crypto/argon2"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// Key file kinds.
const (
	KindCustodian = "custodian"
	KindUser      = "user"
)

const (
	keyFileFormat  = "kyguard-keyfile/1"
	maxKeyFileSize = 1 << 16
	// MinPassphrase is the shortest passphrase a new key file accepts.
	MinPassphrase = 12
)

// ErrPassphrase reports a wrong passphrase or a damaged key file.
var ErrPassphrase = errors.New("kyguard-cli: wrong passphrase or damaged key file")

// KDF holds the Argon2id cost of a key file.
type KDF struct {
	Memory  uint32       `json:"memory_kib"`
	Time    uint32       `json:"time"`
	Threads uint8        `json:"threads"`
	Salt    pqcrypto.B64 `json:"salt"`
}

// keyFile is the on-disk form: public identity in the clear, seeds sealed under a key
// derived from the passphrase with Argon2id.
type keyFile struct {
	Format     string         `json:"format"`
	Kind       string         `json:"kind"`
	ID         pqcrypto.UUID  `json:"id"`
	SigKeyID   pqcrypto.HexID `json:"sig_key_id"`
	EncKeyID   pqcrypto.HexID `json:"enc_key_id,omitzero"`
	KDF        KDF            `json:"argon2id"`
	Nonce      pqcrypto.B64   `json:"nonce"`
	Ciphertext pqcrypto.B64   `json:"ciphertext"`
}

// secrets is what the key file seals.
type secrets struct {
	MLDSA65 pqcrypto.B64 `json:"mldsa65_seed"`
	Ed25519 pqcrypto.B64 `json:"ed25519_seed"`
	XWing   pqcrypto.B64 `json:"xwing_seed,omitzero"`
}

// Key is an opened key file.
type Key struct {
	Kind     string
	ID       pqcrypto.UUID // custodian_id or principal_id
	Sign     *pqcrypto.SigningKey
	Enc      recoverykey.PrivateKey // users only
	SigKeyID pqcrypto.HexID
}

// aad binds the sealed seeds to everything stored in the clear.
func (f *keyFile) aad() ([]byte, error) {
	c := *f
	c.Ciphertext = nil
	return json.Marshal(c)
}

func deriveKey(pass string, k KDF) ([]byte, error) {
	p := password.Params{Memory: k.Memory, Time: k.Time, Threads: k.Threads}
	if err := p.Validate(); err != nil || len(k.Salt) != 16 {
		return nil, fmt.Errorf("kyguard-cli: key file KDF parameters: %w", errors.Join(err, errors.New("salt must be 16 bytes")))
	}
	return argon2.IDKey([]byte(pass), k.Salt, k.Time, k.Memory, k.Threads, 32), nil
}

// writeKeyFile seals k under pass and creates path (0600, never replacing a file).
func writeKeyFile(path, pass string, cost password.Params, k *Key) error {
	b, err := sealKeyFile(pass, cost, k)
	if err != nil {
		return err
	}
	return keyfile.Store(path, b, keyfile.Raw)
}

// sealKeyFile returns the key file contents for k sealed under pass.
func sealKeyFile(pass string, cost password.Params, k *Key) ([]byte, error) {
	if len(pass) < MinPassphrase {
		return nil, fmt.Errorf("kyguard-cli: passphrase must be at least %d characters", MinPassphrase)
	}
	m, e := k.Sign.Seeds()
	s := secrets{MLDSA65: m, Ed25519: e}
	f := keyFile{Format: keyFileFormat, Kind: k.Kind, ID: k.ID, SigKeyID: k.SigKeyID,
		KDF: KDF{cost.Memory, cost.Time, cost.Threads, make([]byte, 16)}, Nonce: make([]byte, 12)}
	if !k.Enc.IsZero() {
		s.XWing = k.Enc.Seed()
		f.EncKeyID = pqcrypto.HexID(k.Enc.Public().ID())
	}
	if _, err := rand.Read(f.KDF.Salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(f.Nonce); err != nil {
		return nil, err
	}
	pt, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	g, err := keyAEAD(pass, f.KDF)
	if err != nil {
		return nil, err
	}
	aad, err := f.aad()
	if err != nil {
		return nil, err
	}
	f.Ciphertext = g.Seal(nil, f.Nonce, pt, aad)
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func keyAEAD(pass string, k KDF) (cipher.AEAD, error) {
	key, err := deriveKey(pass, k)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

// readKeyFile reads the public header of a key file (owner-only file required).
func readKeyFile(path string) (*keyFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	raw, err := keyfile.ReadPrivate(abs, maxKeyFileSize)
	if err != nil {
		return nil, err
	}
	var f keyFile
	if err := json.Unmarshal(raw, &f); err != nil || f.Format != keyFileFormat {
		return nil, fmt.Errorf("kyguard-cli: %s is not a KyGuard key file", path)
	}
	return &f, nil
}

// openKeyFile decrypts a key file and checks that its seeds match its stated key IDs.
func openKeyFile(path, pass, kind string) (*Key, error) {
	f, err := readKeyFile(path)
	if err != nil {
		return nil, err
	}
	if f.Kind != kind {
		return nil, fmt.Errorf("kyguard-cli: %s holds a %s key, not a %s key", path, f.Kind, kind)
	}
	g, err := keyAEAD(pass, f.KDF)
	if err != nil {
		return nil, err
	}
	aad, err := f.aad()
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, f.Nonce, f.Ciphertext, aad)
	if err != nil {
		return nil, ErrPassphrase
	}
	defer clear(pt)
	var s secrets
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, ErrPassphrase
	}
	sk, err := pqcrypto.NewSigningKey(s.MLDSA65, s.Ed25519)
	if err != nil {
		return nil, ErrPassphrase
	}
	k := &Key{Kind: f.Kind, ID: f.ID, Sign: sk}
	if k.SigKeyID, err = sk.Public().SigKeyID(); err != nil || k.SigKeyID != f.SigKeyID {
		return nil, ErrPassphrase
	}
	if kind == KindUser {
		if k.Enc, err = recoverykey.FromSeed(s.XWing); err != nil || pqcrypto.HexID(k.Enc.Public().ID()) != f.EncKeyID {
			return nil, ErrPassphrase
		}
	}
	return k, nil
}
