// Package cptrust is the Control Plane's verified view of the Custodian-signed manifests
// (spec §3.2, §3.7): the imported bundle plus every manifest accepted in order, persisted
// in trust_manifests and replayed through pqcrypto.Trust. It holds no signing key; a
// manifest is admitted only if its signatures verify against the pinned bundle.
package cptrust

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// ErrNoBundle means the operator has not imported the bootstrap bundle yet.
var ErrNoBundle = errors.New("cptrust: bootstrap bundle not imported")

// Trust caches the replayed state and catches up from the database before every use, so
// replicas that accepted manifests are seen without a restart.
type Trust struct {
	st  store.Store
	mu  sync.Mutex
	tr  *pqcrypto.Trust
	seq int64
}

// New returns a Trust over st; it loads lazily.
func New(st store.Store) *Trust { return &Trust{st: st} }

// catchUp loads the bundle if needed and replays manifests appended since the last read.
// Caller holds mu.
func (c *Trust) catchUp(ctx context.Context) error {
	if c.tr == nil {
		b, err := c.st.Guard().Bundle(ctx)
		if errors.Is(err, store.ErrNotFound) {
			return ErrNoBundle
		}
		if err != nil {
			return err
		}
		tr, err := pqcrypto.NewTrust(b.Bundle, pqcrypto.HexID(b.Fingerprint))
		if err != nil {
			return fmt.Errorf("cptrust: stored bundle: %w", err)
		}
		c.tr, c.seq = tr, 0
	}
	ms, err := c.st.Guard().Manifests(ctx, c.seq)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if _, err := c.tr.Accept(m.Manifest); err != nil {
			c.tr = nil // never serve a partial replay
			return fmt.Errorf("cptrust: stored manifest %d: %w", m.Seq, err)
		}
		c.seq = m.Seq
	}
	return nil
}

// View runs fn against the current verified state. fn must not keep tr.
func (c *Trust) View(ctx context.Context, fn func(tr *pqcrypto.Trust) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.catchUp(ctx); err != nil {
		return err
	}
	return fn(c.tr)
}

// Submit verifies a manifest against the current state and persists it. A manifest the
// state already holds is an idempotent success (added false). Equivocation is audited as an
// alert before the error is returned.
func (c *Trust) Submit(ctx context.Context, raw []byte, actor, ip string) (rec *pqcrypto.Record, added bool, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; ; attempt++ {
		if err := c.catchUp(ctx); err != nil {
			return nil, false, err
		}
		before := len(c.tr.Records())
		rec, err := c.tr.Accept(raw)
		if errors.Is(err, pqcrypto.ErrEquivocation) {
			typ, _ := pqcrypto.PeekType(raw)
			log.Printf("[TRUST] ALERT: equivocating %s manifest refused", typ)
			if aerr := c.st.Audit().LogAudit(ctx, &store.AuditRecord{UserID: actor, Action: "trust.equivocation", Resource: "manifest:" + typ, Details: "severity=critical", IPAddress: ip}); aerr != nil {
				return nil, false, aerr
			}
		}
		if err != nil {
			return nil, false, err
		}
		if len(c.tr.Records()) == before {
			return rec, false, nil
		}
		err = c.st.Guard().AppendManifest(ctx, &store.TrustManifest{Seq: c.seq + 1, Type: rec.Type, ScopeID: string(rec.ScopeID),
			Epoch: uint64(rec.Epoch), Digest: string(rec.Digest.Hex()), Manifest: rec.Canonical},
			&store.AuditRecord{UserID: actor, Action: "trust.manifest_accepted", Resource: rec.Type + ":" + string(rec.ScopeID),
				Details: "epoch=" + rec.Epoch.String() + " digest=" + string(rec.Digest.Hex()), IPAddress: ip})
		if err == nil {
			c.seq++
			return rec, true, nil
		}
		c.tr = nil // the in-memory Accept is not persisted: rebuild from the database
		if !errors.Is(err, store.ErrConflict) || attempt > 0 {
			return nil, false, err
		}
	}
}
