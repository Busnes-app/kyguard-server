package pqcrypto

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

var typeRE = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)

// Digest is a 32-byte SHA-256 digest.
type Digest [32]byte

// Hex is the 64-character lowercase hex form.
func (d Digest) Hex() HexID { return HexID(hex.EncodeToString(d[:])) }

// DigestCanonical computes D over already canonical object bytes (§3.1 rule 4): it drops
// the top-level "signatures" and "approvals" members, re-canonicalizes and hashes
// "kyguard/1/<type>" || 0x00 || JCS.
func DigestCanonical(typ string, obj []byte) (Digest, error) {
	if !typeRE.MatchString(typ) {
		return Digest{}, ErrType
	}
	v, err := canonical.Parse(obj)
	if err != nil {
		return Digest{}, err
	}
	o, ok := v.(canonical.Object)
	if !ok {
		return Digest{}, ErrType
	}
	h := sha256.New()
	h.Write([]byte("kyguard/1/" + typ))
	h.Write([]byte{0})
	h.Write(canonical.Encode(o.Without("signatures", "approvals")))
	var d Digest
	h.Sum(d[:0])
	return d, nil
}

// D computes the domain digest of v, which must marshal to a JSON object.
func D(typ string, v any) (Digest, error) {
	b, err := canonical.Marshal(v)
	if err != nil {
		return Digest{}, err
	}
	return DigestCanonical(typ, b)
}
