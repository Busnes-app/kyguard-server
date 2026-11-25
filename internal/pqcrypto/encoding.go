// Package pqcrypto is KyGuard's wire format and crypto core (spec §3.1): strict JSON
// field types, the domain digest D(obj), hybrid ML-DSA-65 + Ed25519 signatures, key IDs,
// the two AAD framings, the HPKE DEK wrap and the AES-256-GCM payload. Stdlib only.
package pqcrypto

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Error is a stable, comparable error code; vectors name it.
type Error string

func (e Error) Error() string { return "pqcrypto: " + string(e) }

// Errors returned by this package.
const (
	ErrCounter   Error = "invalid_counter"
	ErrBase64    Error = "invalid_base64url"
	ErrHex       Error = "invalid_hex_id"
	ErrUUID      Error = "invalid_uuid"
	ErrTime      Error = "invalid_timestamp"
	ErrType      Error = "invalid_type"
	ErrSigAlg    Error = "invalid_signature_alg"
	ErrSignature Error = "invalid_signature"
	ErrKeyLength Error = "invalid_key_length"
	ErrAAD       Error = "invalid_aad"
	ErrDecrypt   Error = "decrypt_failed"
)

// MaxCounter is 2^63-1, so every counter fits a database BIGINT (§3.1 rule 2).
const MaxCounter = 1<<63 - 1

var counterRE = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

// Counter is a decimal-string uint64 capped at MaxCounter.
type Counter uint64

// ParseCounter parses a counter string.
func ParseCounter(s string) (Counter, error) {
	if !counterRE.MatchString(s) {
		return 0, ErrCounter
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > MaxCounter {
		return 0, ErrCounter
	}
	return Counter(n), nil
}

func (c Counter) String() string { return strconv.FormatUint(uint64(c), 10) }

// MarshalJSON refuses a value above MaxCounter rather than emit one nobody accepts.
func (c Counter) MarshalJSON() ([]byte, error) {
	if c > MaxCounter {
		return nil, ErrCounter
	}
	return json.Marshal(c.String())
}

func (c *Counter) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ErrCounter
	}
	n, err := ParseCounter(s)
	if err != nil {
		return err
	}
	*c = n
	return nil
}

var b64 = base64.RawURLEncoding.Strict()

// B64 is a byte field encoded as base64url without padding (§3.1 rule 3).
type B64 []byte

// DecodeB64 decodes strict unpadded base64url. encoding/base64 skips CR and LF even in
// strict mode, so they are refused first.
func DecodeB64(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, ErrBase64
	}
	b, err := b64.DecodeString(s)
	if err != nil {
		return nil, ErrBase64
	}
	return b, nil
}

// EncodeB64 encodes unpadded base64url.
func EncodeB64(b []byte) string { return b64.EncodeToString(b) }

func (b B64) MarshalJSON() ([]byte, error) { return json.Marshal(EncodeB64(b)) }

func (b *B64) UnmarshalJSON(raw []byte) error {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ErrBase64
	}
	d, err := DecodeB64(s)
	if err != nil {
		return err
	}
	*b = d
	return nil
}

var hexIDRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// HexID is a 64-character lowercase hex hash or key ID.
type HexID string

// ZeroHex is the all-zero HexID, the previous hash at receipt seq 1.
const ZeroHex HexID = "0000000000000000000000000000000000000000000000000000000000000000"

func (h HexID) Valid() bool { return hexIDRE.MatchString(string(h)) }

func (h HexID) MarshalJSON() ([]byte, error) {
	if !h.Valid() {
		return nil, ErrHex
	}
	return json.Marshal(string(h))
}

func (h *HexID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || !HexID(s).Valid() {
		return ErrHex
	}
	*h = HexID(s)
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// UUID is a lowercase canonical UUID string.
type UUID string

func (u UUID) Valid() bool { return uuidRE.MatchString(string(u)) }

func (u UUID) MarshalJSON() ([]byte, error) {
	if !u.Valid() {
		return nil, ErrUUID
	}
	return json.Marshal(string(u))
}

func (u *UUID) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil || !UUID(s).Valid() {
		return ErrUUID
	}
	*u = UUID(s)
	return nil
}

// TimeLayout is the one timestamp form: RFC 3339, UTC, whole seconds, "Z".
const TimeLayout = "2006-01-02T15:04:05Z"

// Time is a timestamp encoded as TimeLayout.
type Time struct{ time.Time }

// NewTime truncates t to whole seconds in UTC.
func NewTime(t time.Time) Time { return Time{t.UTC().Truncate(time.Second)} }

func (t Time) MarshalJSON() ([]byte, error) {
	if t.Location() != time.UTC || t.Nanosecond() != 0 || t.Year() < 0 || t.Year() > 9999 {
		return nil, ErrTime // never emit what UnmarshalJSON refuses
	}
	return json.Marshal(t.Format(TimeLayout))
}

func (t *Time) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ErrTime
	}
	p, err := time.Parse(TimeLayout, s)
	if err != nil || p.Format(TimeLayout) != s {
		return ErrTime
	}
	t.Time = p.UTC()
	return nil
}
