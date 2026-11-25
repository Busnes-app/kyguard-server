package pqcrypto

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math"
)

// AAD domains and the HPKE info string (§3.1).
const (
	DomainPayload   = "kyguard/1/payload"
	DomainRecipient = "kyguard/1/recipient"
	DomainOperation = "kyguard/1/operation"
	DEKWrapInfo     = "kyguard/1/dek-wrap"
)

// U64 encodes a counter field as 8 bytes big-endian.
func U64(n Counter) []byte { return binary.BigEndian.AppendUint64(nil, uint64(n)) }

// AAD frames fields as ASCII(domain) || 0x00 || for each f: uint32_be(len(f)) || f.
func AAD(domain string, fields ...[]byte) ([]byte, error) {
	out := append([]byte(domain), 0)
	for _, f := range fields {
		if uint64(len(f)) > math.MaxUint32 {
			return nil, ErrAAD
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out, nil
}

// PayloadAADFields are the payload AAD inputs, in their spec order.
type PayloadAADFields struct {
	EnvelopeKind  string
	EnvelopeID    UUID
	AccountID     UUID
	SecretVersion Counter
	Epoch         Counter // the policy epoch
	PolicyDigest  HexID
	RecoveryEpoch Counter
}

// Bytes returns the payload AAD.
func (f PayloadAADFields) Bytes() ([]byte, error) {
	if !f.EnvelopeID.Valid() || !f.AccountID.Valid() || !f.PolicyDigest.Valid() || !validKind(f.EnvelopeKind) ||
		!validCounters(f.SecretVersion, f.Epoch, f.RecoveryEpoch) {
		return nil, ErrAAD
	}
	return AAD(DomainPayload, []byte(f.EnvelopeKind), []byte(f.EnvelopeID), []byte(f.AccountID),
		U64(f.SecretVersion), U64(f.Epoch), []byte(f.PolicyDigest), U64(f.RecoveryEpoch))
}

// RecipientAADFields are the DEK-wrap AAD inputs, in their spec order.
type RecipientAADFields struct {
	EnvelopeKind  string
	EnvelopeID    UUID
	AccountID     UUID
	SecretVersion Counter
	RecipientID   string // broker_id or principal_id (UUID), or recovery_key_id (hex)
	RecipientType string
	KeyID         HexID
}

// Bytes returns the DEK-wrap AAD.
func (f RecipientAADFields) Bytes() ([]byte, error) {
	if !f.EnvelopeID.Valid() || !f.AccountID.Valid() || !f.KeyID.Valid() ||
		!validKind(f.EnvelopeKind) || !validCounters(f.SecretVersion) || !validRecipient(f.RecipientType, f.RecipientID) {
		return nil, ErrAAD
	}
	return AAD(DomainRecipient, []byte(f.EnvelopeKind), []byte(f.EnvelopeID), []byte(f.AccountID),
		U64(f.SecretVersion), []byte(f.RecipientID), []byte(f.RecipientType), []byte(f.KeyID))
}

func validKind(k string) bool { return k == "managed" || k == "vaulted" }

// validRecipient checks the type enum and that the ID has that type's form.
func validRecipient(typ, id string) bool {
	switch typ {
	case "broker", "user":
		return UUID(id).Valid()
	case "recovery":
		return HexID(id).Valid()
	}
	return false
}

func validCounters(cs ...Counter) bool {
	for _, c := range cs {
		if c > MaxCounter {
			return false
		}
	}
	return true
}

// OpID is the first 16 bytes of SHA-256(AAD("kyguard/1/operation", fields...)), formatted
// as a lowercase UUID string with no version or variant bits forced (§3.4).
func OpID(fields ...[]byte) (UUID, error) {
	a, err := AAD(DomainOperation, fields...)
	if err != nil {
		return "", err
	}
	s := sha256.Sum256(a)
	h := hex.EncodeToString(s[:16])
	return UUID(h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]), nil
}

// RotationOpID is opid(account_id, policy_epoch, occurrence, attempt_n).
func RotationOpID(accountID UUID, policyEpoch, occurrence, attempt Counter) (UUID, error) {
	if !accountID.Valid() || !validCounters(policyEpoch, occurrence, attempt) {
		return "", ErrAAD
	}
	return OpID([]byte(accountID), U64(policyEpoch), U64(occurrence), U64(attempt))
}

// RequestOpID is opid(request_id, attempt_n), for lease cleanup and enrollment.
func RequestOpID(requestID UUID, attempt Counter) (UUID, error) {
	if !requestID.Valid() || !validCounters(attempt) {
		return "", ErrAAD
	}
	return OpID([]byte(requestID), U64(attempt))
}
