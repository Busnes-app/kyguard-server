package pqcrypto

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Custodian is one member of a CustodianSetManifest.
type Custodian struct {
	CustodianID UUID      `json:"custodian_id"`
	SigPub      HybridPub `json:"sig_pub"`
}

// CustodianSetManifest is type custodian_set, deployment scope (§3.2).
type CustodianSetManifest struct {
	Header
	Custodians []Custodian `json:"custodians"`
	Threshold  int         `json:"threshold"`
	Sigs
}

func (m *CustodianSetManifest) validate() error {
	if err := checkHeader(&m.Header, TypeCustodianSet, ScopeDeployment, RoleCustodian); err != nil {
		return err
	}
	if m.Scope.ID != m.DeploymentID || m.Threshold < 1 || m.Threshold > len(m.Custodians) {
		return ErrBody
	}
	ids := make([]UUID, len(m.Custodians))
	for i, c := range m.Custodians {
		ids[i] = c.CustodianID
	}
	if err := distinct(ids); err != nil {
		return err
	}
	_, err := m.ring()
	return err
}

// ring is the custodian key ring; it also rejects a key listed twice.
func (m *CustodianSetManifest) ring() (keyRing, error) {
	r := keyRing{}
	for _, c := range m.Custodians {
		if err := r.add(RoleCustodian, string(c.CustodianID), c.SigPub); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// RecoveryKeyManifest is type recovery_key, deployment scope (§3.2).
type RecoveryKeyManifest struct {
	Header
	RecoveryKeyID        HexID `json:"recovery_key_id"`
	RecoveryPubkey       B64   `json:"recovery_pubkey"`
	Threshold            int   `json:"threshold"`
	TotalShares          int   `json:"total_shares"`
	EscrowDefaultEnabled bool  `json:"escrow_default_enabled"`
	Sigs
}

func (m *RecoveryKeyManifest) validate() error {
	if err := checkHeader(&m.Header, TypeRecoveryKey, ScopeDeployment, RoleCustodian); err != nil {
		return err
	}
	// Shamir topology as ky-primitives/shamir accepts it.
	if m.Scope.ID != m.DeploymentID || m.Threshold < 2 || m.Threshold > m.TotalShares || m.TotalShares > 255 {
		return ErrBody
	}
	if id, err := EncKeyID(m.RecoveryPubkey); err != nil || id != m.RecoveryKeyID {
		return ErrBody
	}
	return nil
}

// BrokerMember is one broker listed in a pool manifest.
type BrokerMember struct {
	BrokerID       UUID      `json:"broker_id"`
	EncPub         B64       `json:"enc_pub"`
	SigPub         HybridPub `json:"sig_pub"`
	MTLSCertSHA256 HexID     `json:"mtls_cert_sha256"`
	Status         string    `json:"status"`
}

// Decommission records the custodians' attestation that a revoked broker is destroyed.
type Decommission struct {
	BrokerID    UUID   `json:"broker_id"`
	Attestation string `json:"attestation"`
}

// BrokerPoolManifest is type pool, pool scope (§3.3).
type BrokerPoolManifest struct {
	Header
	PoolID                  UUID           `json:"pool_id"`
	Members                 []BrokerMember `json:"members"`
	DecommissionedBrokerIDs []Decommission `json:"decommissioned_broker_ids"`
	Sigs
}

// Key statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

func (m *BrokerPoolManifest) validate() error {
	if err := checkHeader(&m.Header, TypePool, ScopePool, RoleCustodian); err != nil {
		return err
	}
	if m.Scope.ID != m.PoolID || m.Members == nil || m.DecommissionedBrokerIDs == nil {
		return ErrBody
	}
	ids := make([]UUID, len(m.Members))
	active := 0
	r := keyRing{}
	status := map[UUID]string{}
	for i, b := range m.Members {
		ids[i] = b.BrokerID
		if b.Status != StatusActive && b.Status != StatusRevoked || !b.MTLSCertSHA256.Valid() {
			return ErrBody
		}
		if b.Status == StatusActive {
			active++
		}
		if _, err := EncKeyID(b.EncPub); err != nil {
			return ErrBody
		}
		if err := r.add(RoleBroker, string(b.BrokerID), b.SigPub); err != nil {
			return ErrBody
		}
		status[b.BrokerID] = b.Status
	}
	if active > 1 { // Phase 1A: at most one active broker per pool
		return ErrUnsupported
	}
	if err := distinct(ids); err != nil {
		return err
	}
	dids := make([]UUID, len(m.DecommissionedBrokerIDs))
	for i, d := range m.DecommissionedBrokerIDs {
		dids[i] = d.BrokerID
		// A decommission refers to a listed, revoked member; it never replaces one.
		if status[d.BrokerID] != StatusRevoked || strings.TrimSpace(d.Attestation) == "" {
			return ErrBody
		}
	}
	return distinct(dids)
}

// Member returns the listed broker, or nil.
func (m *BrokerPoolManifest) Member(id UUID) *BrokerMember {
	for i := range m.Members {
		if m.Members[i].BrokerID == id {
			return &m.Members[i]
		}
	}
	return nil
}

// Active returns the active broker, or nil.
func (m *BrokerPoolManifest) Active() *BrokerMember {
	for i := range m.Members {
		if m.Members[i].Status == StatusActive {
			return &m.Members[i]
		}
	}
	return nil
}

// checkSuccessor enforces that members are never dropped or changed and a revoked member
// never returns to active, so historical broker signatures keep verifying (§3.3, §4.1).
func (m *BrokerPoolManifest) checkSuccessor(prev *BrokerPoolManifest) error {
	for _, p := range prev.Members {
		n := m.Member(p.BrokerID)
		if n == nil || string(n.EncPub) != string(p.EncPub) || n.MTLSCertSHA256 != p.MTLSCertSHA256 ||
			string(n.SigPub.MLDSA65) != string(p.SigPub.MLDSA65) || string(n.SigPub.Ed25519) != string(p.SigPub.Ed25519) ||
			(p.Status == StatusRevoked && n.Status != StatusRevoked) {
			return ErrBody
		}
	}
	for _, d := range prev.DecommissionedBrokerIDs {
		found := false
		for _, n := range m.DecommissionedBrokerIDs {
			found = found || n == d
		}
		if !found {
			return ErrBody
		}
	}
	return nil
}

// Schedule is a rotation schedule: occurrence k is due at anchor_utc + k*interval_seconds.
type Schedule struct {
	AnchorUTC       Time  `json:"anchor_utc"`
	IntervalSeconds int64 `json:"interval_seconds"`
}

// Checkout modes and account kinds.
const (
	ModeProxyOnly = "proxy_only"
	ModeEphemeral = "ephemeral"
	ModeStanding  = "standing"
	KindManaged   = "managed"
	KindVaulted   = "vaulted"
)

// PolicyManifest is type policy, account scope (§3.3). Fields marked managed-only are
// absent on a vaulted policy and present on a managed one.
type PolicyManifest struct {
	Header
	AccountID   UUID   `json:"account_id"`
	AccountKind string `json:"account_kind"`
	// managed only
	PoolID                        UUID   `json:"pool_id,omitzero"`
	TargetDescriptorDigest        HexID  `json:"target_descriptor_digest,omitzero"`
	CheckoutMode                  string `json:"checkout_mode,omitzero"`
	EnrollerPrincipalIDs          []UUID `json:"enroller_principal_ids,omitzero"`
	AutoStandingRelease           *bool  `json:"auto_standing_release,omitzero"`
	StandingRecipientPrincipalIDs []UUID `json:"standing_recipient_principal_ids,omitzero"`
	// both kinds
	AllowedUserPrincipalIDs     []UUID    `json:"allowed_user_principal_ids"`
	AllowedApproverPrincipalIDs []UUID    `json:"allowed_approver_principal_ids"`
	RequiredApproverCount       int       `json:"required_approver_count"`
	MaxCheckoutTTLSeconds       int64     `json:"max_checkout_ttl_seconds"`
	RotationSchedule            *Schedule `json:"rotation_schedule"`
	RecoveryEscrowEnabled       bool      `json:"recovery_escrow_enabled"`
	Sigs
}

// MaxStandingRecipients bounds a policy's standing recipients, so a release receipt with
// all their wraps always fits the chain room the store keeps (store.MaxEnvelope).
const MaxStandingRecipients = 32

func (m *PolicyManifest) validate() error {
	if err := checkHeader(&m.Header, TypePolicy, ScopeAccount, RoleCustodian); err != nil {
		return err
	}
	if m.Scope.ID != m.AccountID || m.AllowedUserPrincipalIDs == nil || m.AllowedApproverPrincipalIDs == nil ||
		m.RequiredApproverCount < 0 || m.MaxCheckoutTTLSeconds < 0 {
		return ErrBody
	}
	if len(m.StandingRecipientPrincipalIDs) > MaxStandingRecipients {
		return ErrBody
	}
	for _, l := range [][]UUID{m.AllowedUserPrincipalIDs, m.AllowedApproverPrincipalIDs, m.EnrollerPrincipalIDs, m.StandingRecipientPrincipalIDs} {
		if err := distinct(l); err != nil {
			return err
		}
	}
	if m.RotationSchedule != nil && m.RotationSchedule.IntervalSeconds <= 0 {
		return ErrBody
	}
	switch m.AccountKind {
	case KindVaulted:
		if m.PoolID != "" || m.TargetDescriptorDigest != "" || m.CheckoutMode != "" || m.EnrollerPrincipalIDs != nil ||
			m.AutoStandingRelease != nil || m.StandingRecipientPrincipalIDs != nil || m.RotationSchedule != nil {
			return ErrBody
		}
	case KindManaged:
		if !m.PoolID.Valid() || !m.TargetDescriptorDigest.Valid() || m.EnrollerPrincipalIDs == nil ||
			m.AutoStandingRelease == nil || m.StandingRecipientPrincipalIDs == nil {
			return ErrBody
		}
		switch m.CheckoutMode {
		case ModeEphemeral, ModeStanding:
		case ModeProxyOnly: // until Phase 3 ships the proxy
			return ErrUnsupported
		default:
			return ErrBody
		}
	default:
		return ErrBody
	}
	return nil
}

// EnrolledKey is one key pair of a principal.
type EnrolledKey struct {
	EncPub   B64       `json:"enc_pub"`
	EncKeyID HexID     `json:"enc_key_id"`
	SigPub   HybridPub `json:"sig_pub"`
	SigKeyID HexID     `json:"sig_key_id"`
	Status   string    `json:"status"`
}

// KeyEnrollmentManifest is type key_enrollment, principal scope (§3.3).
type KeyEnrollmentManifest struct {
	Header
	PrincipalID UUID          `json:"principal_id"`
	Issuer      string        `json:"issuer"`
	Subject     string        `json:"subject"`
	Keys        []EnrolledKey `json:"keys"`
	Sigs
}

func (m *KeyEnrollmentManifest) validate() error {
	if err := checkHeader(&m.Header, TypeKeyEnrollment, ScopePrincipal, RoleCustodian); err != nil {
		return err
	}
	if m.Scope.ID != m.PrincipalID || m.Issuer == "" || m.Subject == "" || len(m.Keys) == 0 {
		return ErrBody
	}
	encs := map[HexID]bool{}
	for _, k := range m.Keys {
		if k.Status != StatusActive && k.Status != StatusRevoked {
			return ErrBody
		}
		if id, err := EncKeyID(k.EncPub); err != nil || id != k.EncKeyID || encs[id] {
			return ErrBody
		}
		encs[k.EncKeyID] = true
		if id, err := k.SigPub.SigKeyID(); err != nil || id != k.SigKeyID {
			return ErrBody
		}
	}
	_, err := m.ring(false)
	return err
}

// ring holds the principal's signing keys in role user; activeOnly drops revoked keys.
func (m *KeyEnrollmentManifest) ring(activeOnly bool) (keyRing, error) {
	r := keyRing{}
	for _, k := range m.Keys {
		if activeOnly && k.Status != StatusActive {
			continue
		}
		if err := r.add(RoleUser, string(m.PrincipalID), k.SigPub); err != nil {
			return nil, ErrBody
		}
	}
	return r, nil
}

// ActiveEncKey returns the active encryption key with this ID, or nil.
func (m *KeyEnrollmentManifest) ActiveEncKey(id HexID) *EnrolledKey {
	for i := range m.Keys {
		if m.Keys[i].Status == StatusActive && m.Keys[i].EncKeyID == id {
			return &m.Keys[i]
		}
	}
	return nil
}

// HasActiveEncKey reports whether the principal has any active encryption key.
func (m *KeyEnrollmentManifest) HasActiveEncKey() bool {
	for _, k := range m.Keys {
		if k.Status == StatusActive {
			return true
		}
	}
	return false
}

// Endpoint is where a target descriptor dials.
type Endpoint struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	TLSCAPEM         string `json:"tls_ca_pem,omitzero"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256,omitzero"`
}

// TargetDescriptor pins where a credential goes (§3.3). It is not signed; the policy pins
// its digest.
type TargetDescriptor struct {
	DescriptorVersion           string                     `json:"descriptor_version"`
	DeploymentID                UUID                       `json:"deployment_id"`
	AccountID                   UUID                       `json:"account_id"`
	AssetID                     UUID                       `json:"asset_id"`
	ConnectorType               string                     `json:"connector_type"`
	AuthenticatedTargetIdentity string                     `json:"authenticated_target_identity"`
	Endpoint                    Endpoint                   `json:"endpoint"`
	ConnectorConfig             map[string]json.RawMessage `json:"connector_config"`
	Dependencies                []json.RawMessage          `json:"dependencies"`
}

// Connector types in the 1A slice.
const (
	ConnectorADLDAPS   = "ad_ldaps"
	ConnectorSSHPasswd = "ssh_passwd"
)

// DecodeTargetDescriptor strictly decodes and validates a descriptor and returns its digest.
// Out-of-slice descriptors are rejected (§3.3).
func DecodeTargetDescriptor(raw []byte) (*TargetDescriptor, Digest, error) {
	var t TargetDescriptor
	canon, err := canonical.Decode(raw, &t)
	if err != nil {
		return nil, Digest{}, err
	}
	if t.DescriptorVersion != "1" || !t.DeploymentID.Valid() || !t.AccountID.Valid() || !t.AssetID.Valid() ||
		t.AuthenticatedTargetIdentity == "" || t.Endpoint.Host == "" || t.Endpoint.Port < 1 || t.Endpoint.Port > 65535 {
		return nil, Digest{}, ErrBody
	}
	if t.Dependencies == nil || len(t.Dependencies) != 0 || t.ConnectorConfig == nil || len(t.ConnectorConfig) != 0 {
		return nil, Digest{}, ErrUnsupported
	}
	switch t.ConnectorType {
	case ConnectorADLDAPS:
		if t.Endpoint.TLSCAPEM == "" || t.Endpoint.SSHHostKeySHA256 != "" {
			return nil, Digest{}, ErrBody
		}
	case ConnectorSSHPasswd:
		b, err := hex.DecodeString(t.Endpoint.SSHHostKeySHA256)
		if err != nil || len(b) != 32 || !HexID(t.Endpoint.SSHHostKeySHA256).Valid() || t.Endpoint.TLSCAPEM != "" {
			return nil, Digest{}, ErrBody
		}
	default:
		return nil, Digest{}, ErrUnsupported
	}
	d, err := DigestCanonical(TypeTarget, canon)
	return &t, d, err
}

// distinct rejects malformed or repeated UUIDs in a list.
func distinct(ids []UUID) error {
	seen := map[UUID]bool{}
	for _, id := range ids {
		if !id.Valid() || seen[id] {
			return ErrBody
		}
		seen[id] = true
	}
	return nil
}
