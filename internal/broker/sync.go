package broker

import (
	"context"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

func (m *Machine) alert(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	log.Printf("[BROKER] ALERT: %s", msg)
	if m.Alerts != nil {
		m.Alerts(msg)
	}
}

// Sync takes the Control Plane's state for the pool and accepts only what verifies (§3.7):
// manifests by the epoch rules, descriptors by the digest their policy pins, and chains that
// extend the broker's own copy. Anything older or diverging is refused and alerted.
func (m *Machine) Sync(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.CP.Sync(ctx)
	if err != nil {
		return err
	}
	for _, raw := range s.Manifests {
		if err := m.acceptManifest(raw); err != nil {
			return err
		}
	}
	var errs []error
	for _, st := range s.Accounts {
		if err := m.syncAccount(ctx, st); err != nil {
			errs = append(errs, fmt.Errorf("account %s: %w", st.AccountID, err))
		}
	}
	return errors.Join(errs...)
}

func (m *Machine) acceptManifest(raw []byte) error {
	before := len(m.Trust.Records())
	rec, err := m.Trust.Accept(raw)
	if err != nil {
		typ, _ := pqcrypto.PeekType(raw)
		m.alert("refused %s manifest from the Control Plane: %v", typ, err)
		return nil
	}
	if len(m.Trust.Records()) == before {
		return nil
	}
	if err := m.J.AppendManifest(rec.Canonical); err != nil {
		return err
	}
	if rec.Type == pqcrypto.TypePolicy {
		a, err := m.J.Account(rec.ScopeID)
		if err != nil {
			return err
		}
		a.PolicyEpoch, a.PolicyPersistedAt = rec.Epoch, m.now()
		return m.J.Save(a)
	}
	return nil
}

func (m *Machine) syncAccount(ctx context.Context, st brokerproto.AccountState) error {
	p, _ := m.Trust.Policy(st.AccountID)
	if p == nil || p.AccountKind != pqcrypto.KindManaged {
		return nil
	}
	if len(st.Descriptor) > 0 {
		td, d, err := pqcrypto.DecodeTargetDescriptor(st.Descriptor)
		if err != nil || d.Hex() != p.TargetDescriptorDigest || td.AccountID != st.AccountID || td.DeploymentID != m.Trust.DeploymentID() {
			m.alert("refused a target descriptor for %s that its policy does not pin", st.AccountID)
		} else if err := m.J.PutDescriptor(d.Hex(), st.Descriptor); err != nil {
			return err
		}
	}
	a, err := m.J.Account(st.AccountID)
	if err != nil {
		return err
	}
	changed := false
	for _, c := range st.Chains {
		ok, err := m.adoptChain(a, c)
		if err != nil {
			m.alert("refused a receipt chain for %s: %v", st.AccountID, err)
			continue
		}
		changed = changed || ok
	}
	if st.HighestVersion > a.HighestVersion {
		a.HighestVersion, changed = st.HighestVersion, true
	}
	if changed {
		return m.J.Save(a)
	}
	return nil
}

// adoptChain merges one Control Plane chain into the broker's copy: a new envelope is taken
// whole once it verifies; a known one only if the Control Plane's receipts extend the
// broker's. It reports whether the copy changed.
func (m *Machine) adoptChain(a *Account, c brokerproto.ChainState) (bool, error) {
	v, err := m.Trust.VerifyEnvelope(c.Envelope, pqcrypto.EnvelopeContext{})
	if err != nil {
		return false, err
	}
	if v.Scope.ID != a.ID {
		return false, pqcrypto.ErrHeader
	}
	ch := pqcrypto.NewChain(v)
	for _, r := range c.Receipts {
		if _, err := m.Trust.Append(ch, r, pqcrypto.ReceiptContext{}); err != nil {
			return false, err
		}
	}
	if v.SecretVersion > a.HighestVersion {
		a.HighestVersion = v.SecretVersion
	}
	for i, local := range a.Chains {
		if !slices.Equal(local.Envelope, c.Envelope) {
			lv, err := m.Trust.VerifyEnvelope(local.Envelope, pqcrypto.EnvelopeContext{})
			if err == nil && lv.EnvelopeID == v.EnvelopeID {
				return false, pqcrypto.ErrChain // the same envelope ID with other bytes
			}
			continue
		}
		lc := pqcrypto.NewChain(v)
		for _, r := range local.Receipts {
			if _, err := m.Trust.Append(lc, r, pqcrypto.ReceiptContext{}); err != nil {
				return false, err
			}
		}
		if err := pqcrypto.ChainExtends(lc.Heads, ch.Heads); err != nil {
			return false, err // older than or diverging from the broker's copy
		}
		if len(ch.Heads) == len(lc.Heads) {
			return false, nil
		}
		a.Chains[i].Receipts = c.Receipts
		return true, nil
	}
	a.Chains = append(a.Chains, ChainCopy{Envelope: c.Envelope, Receipts: c.Receipts})
	return true, nil
}
