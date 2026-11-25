package pqcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"fmt"

	"github.com/Busnes-app/ky-primitives/recoverykey"
)

// DEK and nonce sizes for the payload (§3.1).
const (
	DEKBytes   = 32
	NonceBytes = 12
)

// EncKeyID is enc_key_id: recoverykey.PublicKey.ID(), lowercase hex SHA-256 of the
// 1216-byte X-Wing public key (§3.1 rule 8).
func EncKeyID(pub []byte) (HexID, error) {
	pk, err := recoverykey.ParsePublicKey(pub)
	if err != nil {
		return "", ErrKeyLength
	}
	return HexID(pk.ID()), nil
}

// WrapDEK seals dek to one X-Wing recipient: hpke.NewSender then Seal(aad, dek). It returns
// enc (1120 bytes) and wrapped_dek. The single-shot hpke.Seal takes no AAD and is not used.
func WrapDEK(pub []byte, aad RecipientAADFields, dek []byte) (enc, wrapped []byte, err error) {
	if len(dek) != DEKBytes {
		return nil, nil, ErrKeyLength
	}
	pk, err := recoverykey.ParsePublicKey(pub)
	if err != nil {
		return nil, nil, ErrKeyLength
	}
	if id := HexID(pk.ID()); id != aad.KeyID {
		return nil, nil, ErrAAD // the AAD must name the key being sealed to
	}
	a, err := aad.Bytes()
	if err != nil {
		return nil, nil, err
	}
	enc, s, err := hpke.NewSender(pk.HPKE(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(DEKWrapInfo))
	if err != nil {
		return nil, nil, fmt.Errorf("pqcrypto: %w", err)
	}
	wrapped, err = s.Seal(a, dek)
	if err != nil {
		return nil, nil, fmt.Errorf("pqcrypto: %w", err)
	}
	return enc, wrapped, nil
}

// UnwrapDEK opens a DEK wrap with the recipient's private key.
func UnwrapDEK(sk recoverykey.PrivateKey, aad RecipientAADFields, enc, wrapped []byte) ([]byte, error) {
	if sk.IsZero() || len(enc) != recoverykey.EncapsulationBytes {
		return nil, ErrDecrypt
	}
	if HexID(sk.Public().ID()) != aad.KeyID {
		return nil, ErrAAD
	}
	a, err := aad.Bytes()
	if err != nil {
		return nil, err
	}
	r, err := hpke.NewRecipient(enc, sk.HPKE(), hpke.HKDFSHA256(), hpke.AES256GCM(), []byte(DEKWrapInfo))
	if err != nil {
		return nil, ErrDecrypt
	}
	dek, err := r.Open(a, wrapped)
	if err != nil || len(dek) != DEKBytes {
		return nil, ErrDecrypt
	}
	return dek, nil
}

func gcm(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKBytes {
		return nil, ErrKeyLength
	}
	b, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("pqcrypto: %w", err)
	}
	return cipher.NewGCM(b)
}

// SealPayload is AES-256-GCM(dek, nonce, plaintext, payload AAD). The caller supplies a
// fresh DEK and nonce per envelope.
func SealPayload(dek, nonce []byte, aad PayloadAADFields, plaintext []byte) ([]byte, error) {
	g, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceBytes {
		return nil, ErrKeyLength
	}
	a, err := aad.Bytes()
	if err != nil {
		return nil, err
	}
	return g.Seal(nil, nonce, plaintext, a), nil
}

// OpenPayload reverses SealPayload.
func OpenPayload(dek, nonce []byte, aad PayloadAADFields, ciphertext []byte) ([]byte, error) {
	g, err := gcm(dek)
	if err != nil {
		return nil, err
	}
	if len(nonce) != NonceBytes {
		return nil, ErrDecrypt
	}
	a, err := aad.Bytes()
	if err != nil {
		return nil, err
	}
	pt, err := g.Open(nil, nonce, ciphertext, a)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
