package brokerproto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Paths on the broker listener.
const (
	PathPair    = "/broker/v1/pair"
	PathChannel = "/broker/v1/channel"
	// VersionHeader carries the broker version on the channel handshake.
	VersionHeader = "KyGuard-Broker-Version"
)

const tokenPrefix = "kgp1."

// Token is what a pairing token encodes (§4.1 pairing step 1).
type Token struct {
	CASHA256 pqcrypto.HexID `json:"ca_sha256"`
	Secret   pqcrypto.B64   `json:"secret"`
	URL      string         `json:"url"`
}

// ErrToken reports a malformed pairing token.
var ErrToken = errors.New("brokerproto: malformed pairing token")

// Encode returns the token string the admin hands to the operator.
func (t Token) Encode() (string, error) {
	b, err := canonical.Marshal(t)
	if err != nil {
		return "", err
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseToken decodes a token string.
func ParseToken(s string) (*Token, error) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(s), tokenPrefix)
	if !ok {
		return nil, ErrToken
	}
	b, err := pqcrypto.DecodeB64(raw)
	if err != nil {
		return nil, ErrToken
	}
	var t Token
	if _, err := canonical.Decode(b, &t); err != nil || !t.CASHA256.Valid() || len(t.Secret) != 32 || !strings.HasPrefix(t.URL, "https://") {
		return nil, ErrToken
	}
	return &t, nil
}

// PairRequest is the broker's pairing call (§4.1 pairing step 2).
type PairRequest struct {
	Secret  pqcrypto.B64       `json:"secret"`
	CSR     pqcrypto.B64       `json:"csr"`
	SigPub  pqcrypto.HybridPub `json:"sig_pub"`
	EncPub  pqcrypto.B64       `json:"enc_pub"`
	Version string             `json:"version"`
}

// PairResponse returns the broker certificate and the bundle (§4.1 pairing step 3).
type PairResponse struct {
	BrokerID pqcrypto.UUID `json:"broker_id"`
	Cert     pqcrypto.B64  `json:"cert"`
	CACert   pqcrypto.B64  `json:"ca_cert"`
	Bundle   pqcrypto.B64  `json:"bundle"`
}

// Message is one control channel frame (§4.1): versioned JSON.
type Message struct {
	V    int             `json:"v"`
	Type string          `json:"type"`
	Body json.RawMessage `json:"body,omitempty"`
}

// Message types.
const (
	// MsgNudge asks the broker to re-evaluate its schedule now; it carries no authority
	// and the broker ignores any content (§3.4).
	MsgNudge = "nudge"
)
