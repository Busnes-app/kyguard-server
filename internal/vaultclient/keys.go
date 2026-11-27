package vaultclient

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	Passphrase   = pqcrypto.BrowserPassphrase
	SuiteKeyring = pqcrypto.BrowserSuiteKeyring
	seedBytes    = 32 * 3
)

type UserKey struct {
	Principal pqcrypto.UUID
	Sign      *pqcrypto.SigningKey
	Enc       recoverykey.PrivateKey
}

// CreateKey makes a key for the browser and a self-signed enrollment draft. Brokers
// still require the Custodian quorum before using the public keys.
func CreateKey(deployment pqcrypto.UUID, issuer, subject string) (*UserKey, *pqcrypto.KeyEnrollmentManifest, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return nil, nil, err
	}
	sign, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		return nil, nil, err
	}
	enc, err := recoverykey.Generate()
	if err != nil {
		return nil, nil, err
	}
	sigID, err := sign.Public().SigKeyID()
	if err != nil {
		return nil, nil, err
	}
	pid := pqcrypto.UUID(id.String())
	m := &pqcrypto.KeyEnrollmentManifest{
		Header: pqcrypto.Header{Type: pqcrypto.TypeKeyEnrollment, DeploymentID: deployment, Epoch: 1,
			Scope: pqcrypto.Scope{Kind: pqcrypto.ScopePrincipal, ID: pid}, SignerRole: pqcrypto.RoleCustodian},
		PrincipalID: pid, Issuer: issuer, Subject: subject,
		Keys: []pqcrypto.EnrolledKey{{
			SigPub: sign.Public(), SigKeyID: sigID, EncPub: enc.Public().Bytes(),
			EncKeyID: pqcrypto.HexID(enc.Public().ID()), Status: pqcrypto.StatusActive,
		}},
	}
	if err := pqcrypto.Sign(m, pqcrypto.RoleUser, sign); err != nil {
		return nil, nil, err
	}
	return &UserKey{pid, sign, enc}, m, nil
}

func SealKey(k *UserKey, m *pqcrypto.KeyEnrollmentManifest, method string, ring pqcrypto.UUID, version int, wrappingSecret []byte) (pqcrypto.KeyEnvelope, error) {
	e := pqcrypto.KeyEnvelope{Version: 1, Method: method, Ring: ring, KeyVersion: version, Nonce: make([]byte, 12)}
	if _, err := rand.Read(e.Nonce); err != nil {
		return pqcrypto.KeyEnvelope{}, err
	}
	if method == Passphrase {
		if len(wrappingSecret) < 12 {
			return pqcrypto.KeyEnvelope{}, errors.New("choose an unlock passphrase with at least 12 characters")
		}
		e.Salt = make([]byte, 16)
		if _, err := rand.Read(e.Salt); err != nil {
			return pqcrypto.KeyEnvelope{}, err
		}
	}
	seeds := make([]byte, 0, seedBytes)
	defer func() { clear(seeds) }()
	ml, ed := k.Sign.Seeds()
	enc := k.Enc.Seed()
	defer clear(ml)
	defer clear(ed)
	defer clear(enc)
	seeds = append(seeds, ml...)
	seeds = append(seeds, ed...)
	seeds = append(seeds, enc...)
	g, aad, err := keyCipher(e, m, wrappingSecret)
	if err != nil {
		return pqcrypto.KeyEnvelope{}, err
	}
	e.Ciphertext = g.Seal(nil, e.Nonce, seeds, aad)
	if !e.Valid() {
		return pqcrypto.KeyEnvelope{}, errors.New("invalid wrapping parameters")
	}
	return e, nil
}

func OpenKey(e pqcrypto.KeyEnvelope, m *pqcrypto.KeyEnrollmentManifest, wrappingSecret []byte) (*UserKey, error) {
	if !e.Valid() || len(m.Keys) != 1 {
		return nil, errors.New("invalid encrypted user key")
	}
	g, aad, err := keyCipher(e, m, wrappingSecret)
	if err != nil {
		return nil, err
	}
	seeds, err := g.Open(nil, e.Nonce, e.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("the user key could not be unlocked")
	}
	defer clear(seeds)
	sig, err := pqcrypto.NewSigningKey(seeds[:32], seeds[32:64])
	if err != nil {
		return nil, err
	}
	enc, err := recoverykey.FromSeed(seeds[64:])
	if err != nil {
		return nil, err
	}
	id, err := sig.Public().SigKeyID()
	if err != nil || id != m.Keys[0].SigKeyID || enc.Public().ID() != string(m.Keys[0].EncKeyID) {
		return nil, errors.New("the user key does not match its signed enrollment")
	}
	return &UserKey{m.PrincipalID, sig, enc}, nil
}

func keyCipher(e pqcrypto.KeyEnvelope, m *pqcrypto.KeyEnrollmentManifest, wrappingSecret []byte) (cipher.AEAD, []byte, error) {
	digest, err := pqcrypto.ObjDigest(m)
	if err != nil {
		return nil, nil, err
	}
	// The signed draft digest commits to the deployment, principal, issuer, subject
	// and both public keys. The suite subkey is also scoped to the keyring generation.
	aad, err := canonical.Marshal([]any{"kyguard/browser-key/1", digest.Hex(), e.Method, string(e.Ring), e.KeyVersion})
	if err != nil {
		return nil, nil, err
	}
	var key []byte
	switch e.Method {
	case Passphrase:
		// Version 1 freezes the suite password defaults at format creation.
		key = argon2.IDKey(wrappingSecret, e.Salt, 3, 64*1024, 4, 32)
	case SuiteKeyring:
		if len(wrappingSecret) != 32 {
			return nil, nil, errors.New("invalid KyIdentity app subkey")
		}
		key, err = hkdf.Key(sha256.New, wrappingSecret, nil, string(aad), 32)
	default:
		return nil, nil, errors.New("unknown user key wrapping method")
	}
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	g, err := cipher.NewGCM(block)
	return g, aad, err
}
