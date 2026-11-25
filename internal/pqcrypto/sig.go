package pqcrypto

import (
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// HybridAlg is the only signature algorithm (§3.1 rules 5 and 6).
const HybridAlg = "mldsa65+ed25519"

// SeedBytes is the length of each signing-key seed.
const SeedBytes = 32

// HybridSig carries both signature halves over the same D(obj).
type HybridSig struct {
	Alg     string `json:"alg"`
	MLDSA65 B64    `json:"mldsa65"`
	Ed25519 B64    `json:"ed25519"`
}

// HybridPub is a hybrid signing public key.
type HybridPub struct {
	Alg     string `json:"alg"`
	MLDSA65 B64    `json:"mldsa65"`
	Ed25519 B64    `json:"ed25519"`
}

// SigKeyID is hex(SHA-256("kyguard/1/sigkey" || 0x00 || mldsa65_pk || ed25519_pk)).
func (p HybridPub) SigKeyID() (HexID, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("kyguard/1/sigkey\x00"))
	h.Write(p.MLDSA65)
	h.Write(p.Ed25519)
	return HexID(hex.EncodeToString(h.Sum(nil))), nil
}

func (p HybridPub) check() error {
	if p.Alg != HybridAlg {
		return ErrSigAlg
	}
	if len(p.MLDSA65) != mldsa.MLDSA65PublicKeySize || len(p.Ed25519) != ed25519.PublicKeySize {
		return ErrKeyLength
	}
	return nil
}

// Verify reports whether both halves of sig verify over d under p.
func (p HybridPub) Verify(d Digest, sig HybridSig) error {
	if err := p.check(); err != nil {
		return err
	}
	if sig.Alg != HybridAlg {
		return ErrSigAlg
	}
	if len(sig.MLDSA65) != mldsa.MLDSA65SignatureSize || len(sig.Ed25519) != ed25519.SignatureSize {
		return ErrSignature
	}
	pk, err := mldsa.NewPublicKey(mldsa.MLDSA65(), p.MLDSA65)
	if err != nil {
		return ErrKeyLength
	}
	// Both halves are always checked; either failing rejects.
	errM := mldsa.Verify(pk, d[:], sig.MLDSA65, &mldsa.Options{Context: ""})
	okE := ed25519.Verify(ed25519.PublicKey(p.Ed25519), d[:], sig.Ed25519)
	if errM != nil || !okE {
		return ErrSignature
	}
	return nil
}

// SigningKey is a hybrid private signing key.
type SigningKey struct {
	mldsa *mldsa.PrivateKey
	ed    ed25519.PrivateKey
}

// NewSigningKey rebuilds a key from its two 32-byte seeds.
func NewSigningKey(mldsaSeed, edSeed []byte) (*SigningKey, error) {
	if len(mldsaSeed) != SeedBytes || len(edSeed) != ed25519.SeedSize {
		return nil, ErrKeyLength
	}
	m, err := mldsa.NewPrivateKey(mldsa.MLDSA65(), mldsaSeed)
	if err != nil {
		return nil, fmt.Errorf("pqcrypto: %w", err)
	}
	return &SigningKey{mldsa: m, ed: ed25519.NewKeyFromSeed(edSeed)}, nil
}

// GenerateSigningKey makes a fresh hybrid key.
func GenerateSigningKey() (*SigningKey, error) {
	m, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		return nil, fmt.Errorf("pqcrypto: %w", err)
	}
	_, ed, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("pqcrypto: %w", err)
	}
	return &SigningKey{mldsa: m, ed: ed}, nil
}

// Seeds returns copies of the ML-DSA and Ed25519 seeds, for an encrypted key file.
func (k *SigningKey) Seeds() (mldsaSeed, edSeed []byte) {
	return k.mldsa.Bytes(), append([]byte(nil), k.ed.Seed()...)
}

// Public returns the hybrid public key.
func (k *SigningKey) Public() HybridPub {
	return HybridPub{
		Alg:     HybridAlg,
		MLDSA65: k.mldsa.PublicKey().Bytes(),
		Ed25519: append(B64(nil), k.ed.Public().(ed25519.PublicKey)...),
	}
}

// Sign signs d with both halves: ML-DSA-65 with an empty context, pure Ed25519.
func (k *SigningKey) Sign(d Digest) (HybridSig, error) {
	m, err := k.mldsa.Sign(nil, d[:], &mldsa.Options{Context: ""})
	if err != nil {
		return HybridSig{}, fmt.Errorf("pqcrypto: %w", err)
	}
	return HybridSig{Alg: HybridAlg, MLDSA65: m, Ed25519: ed25519.Sign(k.ed, d[:])}, nil
}
