package cli

import (
	"errors"
	"sort"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// show prints a draft decoded for review (§3.2 rule 4). Strings from the object or the
// Control Plane are printed quoted, so control characters cannot rewrite the screen.
func (a *App) show(tr *pqcrypto.Trust, m pqcrypto.Signed, d pqcrypto.Digest, dr *Draft) error {
	h := pqcrypto.HeaderOf(m)
	a.printf("type        %s\ndeployment  %s\nscope       %s %s\nepoch       %s", h.Type, h.DeploymentID, h.Scope.Kind, h.Scope.ID, h.Epoch)
	if r := tr.Lookup(h.Type, h.Scope.ID); r != nil {
		a.printf(" (verified epoch %s)", r.Epoch)
	}
	a.printf("\ndigest      %s\n", d.Hex())
	keys := make([]string, 0, len(dr.Labels))
	for k := range dr.Labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		a.printf("UNVERIFIED label from the Control Plane: %q = %q\n", k, dr.Labels[k])
	}
	switch o := m.(type) {
	case *pqcrypto.CustodianSetManifest:
		a.printf("threshold   %d of %d\n", o.Threshold, len(o.Custodians))
		if o.Threshold == 1 && len(o.Custodians) == 1 {
			a.printf("WARNING: a 1-of-1 custodian set\n")
		}
		for _, c := range o.Custodians {
			id, _ := c.SigPub.SigKeyID()
			a.printf("custodian   %s sig_key_id %s\n", c.CustodianID, id)
		}
	case *pqcrypto.RecoveryKeyManifest:
		a.printf("recovery_key_id %s, shares %d of %d, escrow default %t\n", o.RecoveryKeyID, o.Threshold, o.TotalShares, o.EscrowDefaultEnabled)
	case *pqcrypto.BrokerPoolManifest:
		a.printf("pool        %s\nCheck each broker against `kyguard-broker pair` output on its host:\n", o.PoolID)
		for _, b := range o.Members {
			sid, _ := b.SigPub.SigKeyID()
			eid, _ := pqcrypto.EncKeyID(b.EncPub)
			a.printf("broker      %s %s\n  sig_key_id %s\n  enc_key_id %s\n  cert_sha256 %s\n", b.BrokerID, b.Status, sid, eid, b.MTLSCertSHA256)
		}
		for _, x := range o.DecommissionedBrokerIDs {
			a.printf("decommissioned %s attestation %q\n", x.BrokerID, x.Attestation)
		}
	case *pqcrypto.KeyEnrollmentManifest:
		a.printf("Check against the user's `kyguard-cli enroll` output:\nprincipal_id %s\nissuer      %q\nsubject     %q\n", o.PrincipalID, o.Issuer, o.Subject)
		for _, k := range o.Keys {
			a.printf("key         %s\n  sig_key_id %s\n  enc_key_id %s\n", k.Status, k.SigKeyID, k.EncKeyID)
		}
	case *pqcrypto.PolicyManifest:
		return a.showPolicy(tr, o, dr)
	}
	return nil
}

// ErrTargetUnverified reports a managed policy whose target descriptor was not supplied or
// does not match the policy's digest; the CLI refuses to sign it.
var ErrTargetUnverified = errors.New("kyguard-cli sign: target descriptor missing or not matching the policy's digest")

func (a *App) showPolicy(tr *pqcrypto.Trust, p *pqcrypto.PolicyManifest, dr *Draft) error {
	a.printf("account     %s (%s)\n", p.AccountID, p.AccountKind)
	if p.AccountKind == pqcrypto.KindManaged {
		td, d, err := pqcrypto.DecodeTargetDescriptor(dr.Target)
		if err != nil || d.Hex() != p.TargetDescriptorDigest || td.AccountID != p.AccountID || td.DeploymentID != p.DeploymentID {
			return ErrTargetUnverified
		}
		a.printf("target      %s %q at %q port %d (digest %s, recomputed)\n", td.ConnectorType, td.AuthenticatedTargetIdentity, td.Endpoint.Host, td.Endpoint.Port, d.Hex())
		if td.Endpoint.SSHHostKeySHA256 != "" {
			a.printf("  ssh_host_key_sha256 %s\n", td.Endpoint.SSHHostKeySHA256)
		}
		a.printf("pool        %s", p.PoolID)
		if pool := tr.Pool(p.PoolID); pool != nil && pool.Active() != nil {
			a.printf(" (verified, active broker %s)", pool.Active().BrokerID)
		} else {
			a.printf(" (NOT VERIFIED: no pool manifest imported)")
		}
		a.printf("\ncheckout    %s, auto standing release %t, max ttl %ds\n", p.CheckoutMode, *p.AutoStandingRelease, p.MaxCheckoutTTLSeconds)
		a.principals(tr, "enrollers", p.EnrollerPrincipalIDs)
		a.principals(tr, "standing recipients", p.StandingRecipientPrincipalIDs)
	}
	a.principals(tr, "allowed users", p.AllowedUserPrincipalIDs)
	a.principals(tr, "approvers", p.AllowedApproverPrincipalIDs)
	a.printf("approvals required %d, recovery escrow %t\n", p.RequiredApproverCount, p.RecoveryEscrowEnabled)
	if s := p.RotationSchedule; s != nil {
		a.printf("rotation    every %ds from %s\n", s.IntervalSeconds, s.AnchorUTC.Format(pqcrypto.TimeLayout))
	}
	return nil
}

// principals resolves IDs to issuer and subject from verified key enrollments only.
func (a *App) principals(tr *pqcrypto.Trust, label string, ids []pqcrypto.UUID) {
	a.printf("%s:\n", label)
	if len(ids) == 0 {
		a.printf("  (none)\n")
	}
	for _, id := range ids {
		if ke := tr.Enrollment(id); ke != nil {
			a.printf("  %s %q %q\n", id, ke.Issuer, ke.Subject)
		} else {
			a.printf("  %s UNKNOWN: no verified key enrollment\n", id)
		}
	}
}
