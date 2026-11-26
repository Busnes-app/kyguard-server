package pqcrypto

import (
	"crypto/rand"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// SealTo is one recipient of a new envelope.
type SealTo struct {
	Type string // RecipientBroker, RecipientUser or RecipientRecovery
	ID   string // broker_id, principal_id or recovery_key_id
	Pub  []byte // X-Wing public key
}

// payload is the plaintext an envelope seals (§3.5).
type payload struct {
	Password string `json:"password"`
}

// Seal builds an unsigned envelope over password with a fresh DEK and nonce, wrapped to each
// recipient. The caller signs it. The DEK is wiped before Seal returns; the password string
// built for the JSON payload cannot be (a known limit, §4.1).
func Seal(h Header, kind string, id UUID, version Counter, policyDigest HexID, recoveryEpoch Counter, created time.Time, password []byte, to []SealTo) (*SecretEnvelope, error) {
	e := &SecretEnvelope{Header: h, EnvelopeKind: kind, EnvelopeID: id, SecretVersion: version, PolicyDigest: policyDigest,
		RecoveryEpoch: recoveryEpoch, CreatedAt: NewTime(created), Nonce: make([]byte, NonceBytes), Recipients: []Recipient{}}
	dek := make([]byte, DEKBytes)
	defer clear(dek)
	if _, err := rand.Read(dek); err != nil {
		return nil, err
	}
	if _, err := rand.Read(e.Nonce); err != nil {
		return nil, err
	}
	pt, err := canonical.Marshal(payload{string(password)})
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	if e.Ciphertext, err = SealPayload(dek, e.Nonce, e.PayloadAAD(), pt); err != nil {
		return nil, err
	}
	for _, r := range to {
		kid, err := EncKeyID(r.Pub)
		if err != nil {
			return nil, err
		}
		rec := Recipient{RecipientType: r.Type, RecipientID: r.ID, KeyID: kid}
		if rec.Enc, rec.WrappedDEK, err = WrapDEK(r.Pub, e.RecipientAAD(rec), dek); err != nil {
			return nil, err
		}
		e.Recipients = append(e.Recipients, rec)
	}
	return e, nil
}

// OpenDEK unwraps the envelope's DEK for the recipient whose key is sk. The caller wipes it.
func (e *SecretEnvelope) OpenDEK(typ, id string, sk recoverykey.PrivateKey) ([]byte, error) {
	for _, r := range e.Recipients {
		if r.RecipientType == typ && r.RecipientID == id {
			return UnwrapDEK(sk, e.RecipientAAD(r), r.Enc, r.WrappedDEK)
		}
	}
	return nil, ErrRecipients
}

// OpenPassword returns the sealed password; the caller wipes it.
func (e *SecretEnvelope) OpenPassword(dek []byte) ([]byte, error) {
	pt, err := OpenPayload(dek, e.Nonce, e.PayloadAAD(), e.Ciphertext)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var p payload
	if _, err := canonical.Decode(pt, &p); err != nil {
		return nil, ErrDecrypt
	}
	return []byte(p.Password), nil
}

// WrapTo wraps an open DEK to one more user key, with the envelope's DEK-wrap AAD (§3.6
// checkout delivery, rewrap_user).
func (e *SecretEnvelope) WrapTo(dek []byte, principal UUID, pub []byte) (Recipient, error) {
	kid, err := EncKeyID(pub)
	if err != nil {
		return Recipient{}, err
	}
	r := Recipient{RecipientType: RecipientUser, RecipientID: string(principal), KeyID: kid}
	r.Enc, r.WrappedDEK, err = WrapDEK(pub, e.RecipientAAD(r), dek)
	return r, err
}
