package brokerproto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
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

// Message is one control channel frame (§4.1): versioned JSON. A broker request carries a
// non-zero ID; the Control Plane answers with MsgResult under the same ID, with Error set on
// refusal. Pushes from the Control Plane carry ID 0.
type Message struct {
	V     int             `json:"v"`
	Type  string          `json:"type"`
	ID    uint64          `json:"id,omitempty"`
	Body  json.RawMessage `json:"body,omitempty"`
	Error string          `json:"error,omitempty"`
}

// Message types.
const (
	// MsgNudge asks the broker to re-evaluate its schedule now; it carries no authority
	// and the broker ignores any content (§3.4).
	MsgNudge = "nudge"
	// MsgResult answers a broker request.
	MsgResult = "result"

	// Broker requests.
	MsgSync        = "sync"         // SyncRequest -> SyncReply
	MsgSyncAccount = "sync_account" // SyncAccountRequest -> AccountState
	MsgReserve     = "reserve"      // ReserveRequest -> ReserveReply
	MsgEnvelope    = "envelope"     // EnvelopeRequest
	MsgIntent      = "intent"       // IntentRequest; the reply is the §4.3 rule 2 acknowledgement
	MsgReceipts    = "receipts"     // ReceiptsRequest
	MsgStatus      = "status"       // StatusRequest
	MsgAccept      = "accept"       // AcceptRequest: §4.5 step 2 acceptance CAS

	// Control Plane pushes.
	MsgEnroll = "enroll" // EnrollPush: a relayed enroll transaction and its candidate
)

// Signed objects travel base64url-encoded so their canonical bytes survive any JSON
// re-encoding.

// MaxFrame is the largest channel frame either end reads.
const MaxFrame = 4 << 20

// SyncPage is the most manifests one sync reply carries; SyncAccountsPage how many account
// IDs.
const (
	SyncPage         = 64
	SyncAccountsPage = 4096
)

// SyncBudget bounds the encoded manifests of one sync page and the encoded descriptor and
// chains of one sync_account reply. A page that would be empty carries its first item
// anyway; one manifest is at most cptrust.MaxManifest and one chain with its descriptor at
// most store.MaxChain and store.MaxDescriptor, so a page stays under MaxFrame. It is a
// variable only so tests can lower it.
var SyncBudget = syncBudget

// SyncChains is the most newer chains one sync_account reply carries, and so about the
// most the Control Plane reads for it (decision 62). A variable only so tests can lower it.
var SyncChains = 64

const syncBudget = 2 << 20

// A budget-sized page or one maximal manifest, base64url-encoded, leaves 1 MiB of a frame
// for JSON framing, and one maximal chain with its descriptor fits the budget (a negative
// constant fails to compile).
const (
	_ = uint(MaxFrame - 1<<20 - syncBudget)
	_ = uint(MaxFrame - 1<<20 - (cptrust.MaxManifest+2)/3*4)
	_ = uint(syncBudget - 64<<10 - (store.MaxChain+store.MaxDescriptor+2)/3*4)
)

// SyncRequest pages through the verified manifests, then the pool's account IDs.
type SyncRequest struct {
	ManifestsAfter int           `json:"manifests_after"`
	AccountsAfter  pqcrypto.UUID `json:"accounts_after,omitzero"`
}

// SyncReply is one page: manifests while any remain, then account IDs in order. Done is
// set on the last page.
type SyncReply struct {
	Manifests []pqcrypto.B64  `json:"manifests"`
	Accounts  []pqcrypto.UUID `json:"accounts"`
	Done      bool            `json:"done"`
}

// SyncAccountRequest asks for one account, within SyncBudget per reply: its current and
// unterminated chains at or below AfterVersion and every chain above it, in version order,
// starting above From. More means call again with the same AfterVersion and From set to the
// highest version received.
type SyncAccountRequest struct {
	AccountID    pqcrypto.UUID    `json:"account_id"`
	AfterVersion pqcrypto.Counter `json:"after_version"`
	From         pqcrypto.Counter `json:"from,omitzero"`
}

// AccountState is one account as the Control Plane holds it.
type AccountState struct {
	AccountID      pqcrypto.UUID    `json:"account_id"`
	Descriptor     pqcrypto.B64     `json:"descriptor,omitzero"`
	Chains         []ChainState     `json:"chains"`
	HighestVersion pqcrypto.Counter `json:"highest_version"`
	More           bool             `json:"more,omitzero"`
}

// ChainState is an envelope and its receipts in order.
type ChainState struct {
	Envelope pqcrypto.B64   `json:"envelope"`
	Receipts []pqcrypto.B64 `json:"receipts"`
}

// ReserveRequest takes the account's rotation lock and a new secret_version (§3.5).
// Reported is the broker's highest seen version, which the Control Plane never goes below.
type ReserveRequest struct {
	AccountID   pqcrypto.UUID    `json:"account_id"`
	OperationID pqcrypto.UUID    `json:"operation_id"`
	Reported    pqcrypto.Counter `json:"reported"`
}

// ReserveReply is the allocated version.
type ReserveReply struct {
	SecretVersion pqcrypto.Counter `json:"secret_version"`
}

// EnvelopeRequest stores a sealed candidate under the operation's lock.
type EnvelopeRequest struct {
	OperationID pqcrypto.UUID `json:"operation_id"`
	Envelope    pqcrypto.B64  `json:"envelope"`
}

// Intent is the mutating intent of §4.3 rule 2, journaled by the broker and mirrored in
// rotation_runs before any write is sent.
type Intent struct {
	BrokerID      pqcrypto.UUID    `json:"broker_id"`
	OperationID   pqcrypto.UUID    `json:"operation_id"`
	AccountID     pqcrypto.UUID    `json:"account_id"`
	SecretVersion pqcrypto.Counter `json:"secret_version"`
	Endpoint      string           `json:"endpoint"`
	Baseline      string           `json:"baseline"`
	OldEnvelopeID pqcrypto.UUID    `json:"old_envelope_id,omitzero"`
	NewEnvelopeID pqcrypto.UUID    `json:"new_envelope_id"`
}

// IntentRequest carries the canonical intent.
type IntentRequest struct {
	Intent pqcrypto.B64 `json:"intent"`
}

// ReceiptsRequest appends signed receipts for one operation (§4.3 rule 7). The Control Plane
// derives the current envelope, the run state and the lock release from the verified
// receipts alone.
type ReceiptsRequest struct {
	OperationID pqcrypto.UUID  `json:"operation_id"`
	AccountID   pqcrypto.UUID  `json:"account_id"`
	Receipts    []pqcrypto.B64 `json:"receipts"`
}

// StatusRequest reports an account's operational health (§8.1) and, for an unknown
// outcome, its run state.
type StatusRequest struct {
	AccountID   pqcrypto.UUID `json:"account_id"`
	Health      string        `json:"health"`
	Reason      string        `json:"reason,omitzero"`
	OperationID pqcrypto.UUID `json:"operation_id,omitzero"`
	RunState    string        `json:"run_state,omitzero"`
}

// AcceptRequest asks the Control Plane to mark an enrollment reservation accepted.
type AcceptRequest struct {
	AccountID   pqcrypto.UUID `json:"account_id"`
	OperationID pqcrypto.UUID `json:"operation_id"`
}

// EnrollPush relays an enroll transaction and its candidate envelope to the broker. The
// broker verifies both itself.
type EnrollPush struct {
	Tx       pqcrypto.B64 `json:"tx"`
	Envelope pqcrypto.B64 `json:"envelope"`
}
