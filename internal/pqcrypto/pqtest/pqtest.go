// Package pqtest builds signed KyGuard deployments for tests outside internal/pqcrypto: a
// bootstrap bundle with two custodians (M = 2) and helpers that sign manifests with them.
// Import it from _test.go files only.
package pqtest

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

// Deployment is a test deployment and its custodian keys.
type Deployment struct {
	ID          pqcrypto.UUID
	Custodians  []*pqcrypto.SigningKey
	Recovery    recoverykey.PrivateKey
	Bundle      []byte
	Fingerprint pqcrypto.HexID
}

// UUID returns a random lowercase UUIDv7-shaped ID.
func UUID() pqcrypto.UUID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x70
	b[8] = b[8]&0x3f | 0x80
	return pqcrypto.UUID(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

// New builds a deployment with two custodians and threshold 2.
func New(t testing.TB) *Deployment {
	t.Helper()
	d := &Deployment{ID: UUID()}
	for range 2 {
		k, err := pqcrypto.GenerateSigningKey()
		if err != nil {
			t.Fatal(err)
		}
		d.Custodians = append(d.Custodians, k)
	}
	rk, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	d.Recovery = rk
	cs := pqcrypto.CustodianSetManifest{Header: d.Header(pqcrypto.TypeCustodianSet, pqcrypto.ScopeDeployment, d.ID, 1), Threshold: 2}
	for _, k := range d.Custodians {
		cs.Custodians = append(cs.Custodians, pqcrypto.Custodian{CustodianID: UUID(), SigPub: k.Public()})
	}
	d.sign(t, &cs)
	rm := pqcrypto.RecoveryKeyManifest{Header: d.Header(pqcrypto.TypeRecoveryKey, pqcrypto.ScopeDeployment, d.ID, 1),
		RecoveryKeyID: pqcrypto.HexID(rk.Public().ID()), RecoveryPubkey: rk.Public().Bytes(), Threshold: 2, TotalShares: 3}
	d.sign(t, &rm)
	d.Bundle = Canon(t, &pqcrypto.Bundle{DeploymentID: d.ID, CustodianSet: cs, RecoveryKey: rm})
	fp, err := pqcrypto.BundleFingerprint(d.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	d.Fingerprint = fp.Hex()
	return d
}

// Header is a custodian-signed header in this deployment.
func (d *Deployment) Header(typ, kind string, scope pqcrypto.UUID, epoch pqcrypto.Counter) pqcrypto.Header {
	return pqcrypto.Header{Type: typ, DeploymentID: d.ID, Epoch: epoch, Scope: pqcrypto.Scope{Kind: kind, ID: scope}, SignerRole: pqcrypto.RoleCustodian}
}

func (d *Deployment) sign(t testing.TB, o pqcrypto.Signed) {
	t.Helper()
	for _, k := range d.Custodians {
		if err := pqcrypto.Sign(o, pqcrypto.RoleCustodian, k); err != nil {
			t.Fatal(err)
		}
	}
}

// Signed signs o with every custodian and returns its canonical JSON.
func (d *Deployment) Signed(t testing.TB, o pqcrypto.Signed) []byte {
	t.Helper()
	d.sign(t, o)
	return Canon(t, o)
}

// Trust returns a Trust pinned to this deployment.
func (d *Deployment) Trust(t testing.TB) *pqcrypto.Trust {
	t.Helper()
	tr, err := pqcrypto.NewTrust(d.Bundle, d.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// Broker is a broker's identity as a pool manifest lists it.
type Broker struct {
	ID         pqcrypto.UUID
	Sig        *pqcrypto.SigningKey
	Enc        recoverykey.PrivateKey
	CertSHA256 pqcrypto.HexID
}

// Member lists b in a pool manifest with status.
func (b *Broker) Member(status string) pqcrypto.BrokerMember {
	return pqcrypto.BrokerMember{BrokerID: b.ID, EncPub: b.Enc.Public().Bytes(), SigPub: b.Sig.Public(), MTLSCertSHA256: b.CertSHA256, Status: status}
}

// Pool returns a signed pool manifest.
func (d *Deployment) Pool(t testing.TB, pool pqcrypto.UUID, epoch pqcrypto.Counter, members []pqcrypto.BrokerMember, decom []pqcrypto.Decommission) []byte {
	t.Helper()
	if decom == nil {
		decom = []pqcrypto.Decommission{}
	}
	return d.Signed(t, &pqcrypto.BrokerPoolManifest{Header: d.Header(pqcrypto.TypePool, pqcrypto.ScopePool, pool, epoch),
		PoolID: pool, Members: members, DecommissionedBrokerIDs: decom})
}

// Canon returns the canonical JSON of v.
func Canon(t testing.TB, v any) []byte {
	t.Helper()
	b, err := canonical.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// SSHTarget returns a canonical ssh_passwd descriptor and its digest.
func (d *Deployment) SSHTarget(t testing.TB, account, asset pqcrypto.UUID, host string, port int, user string, hostKeySHA256 pqcrypto.HexID) ([]byte, pqcrypto.HexID) {
	t.Helper()
	return d.target(t, &pqcrypto.TargetDescriptor{DescriptorVersion: "1", DeploymentID: d.ID, AccountID: account, AssetID: asset,
		ConnectorType: pqcrypto.ConnectorSSHPasswd, AuthenticatedTargetIdentity: user,
		Endpoint: pqcrypto.Endpoint{Host: host, Port: port, SSHHostKeySHA256: string(hostKeySHA256)}})
}

// ADTarget returns a canonical ad_ldaps descriptor and its digest.
func (d *Deployment) ADTarget(t testing.TB, account, asset pqcrypto.UUID, host string, port int, dn, caPEM string) ([]byte, pqcrypto.HexID) {
	t.Helper()
	return d.target(t, &pqcrypto.TargetDescriptor{DescriptorVersion: "1", DeploymentID: d.ID, AccountID: account, AssetID: asset,
		ConnectorType: pqcrypto.ConnectorADLDAPS, AuthenticatedTargetIdentity: dn,
		Endpoint: pqcrypto.Endpoint{Host: host, Port: port, TLSCAPEM: caPEM}})
}

func (d *Deployment) target(t testing.TB, td *pqcrypto.TargetDescriptor) ([]byte, pqcrypto.HexID) {
	t.Helper()
	td.ConnectorConfig, td.Dependencies = map[string]json.RawMessage{}, []json.RawMessage{}
	raw := Canon(t, td)
	_, dg, err := pqcrypto.DecodeTargetDescriptor(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, dg.Hex()
}

// ManagedPolicy is an unsigned managed policy with no users, no approvals, escrow off and
// no schedule; tests adjust it and sign it with Signed.
func (d *Deployment) ManagedPolicy(account, pool pqcrypto.UUID, epoch pqcrypto.Counter, target pqcrypto.HexID) *pqcrypto.PolicyManifest {
	f := false
	return &pqcrypto.PolicyManifest{Header: d.Header(pqcrypto.TypePolicy, pqcrypto.ScopeAccount, account, epoch),
		AccountID: account, AccountKind: pqcrypto.KindManaged, PoolID: pool, TargetDescriptorDigest: target,
		CheckoutMode: pqcrypto.ModeEphemeral, EnrollerPrincipalIDs: []pqcrypto.UUID{}, AutoStandingRelease: &f,
		StandingRecipientPrincipalIDs: []pqcrypto.UUID{}, AllowedUserPrincipalIDs: []pqcrypto.UUID{},
		AllowedApproverPrincipalIDs: []pqcrypto.UUID{}, MaxCheckoutTTLSeconds: 3600}
}
