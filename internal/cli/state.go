package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// ErrNotPinned reports a CLI with no trust pin: it refuses every manifest and opens no
// secret until `kyguard-cli trust` pins a bootstrap fingerprint.
var ErrNotPinned = errors.New("kyguard-cli: no trust pin; run `kyguard-cli trust <fingerprint>` first")

const stateFile = "trust.json"

// state is the persisted trust: the pin, the verified bundle and every manifest accepted,
// in order. Replaying it rebuilds the high-water mark per (type, scope.id). Signed holds
// this CLI's signing commitments: the highest (epoch, digest) it has signed per
// (type, scope.id), including drafts that never reached quorum.
type state struct {
	Fingerprint pqcrypto.HexID    `json:"fingerprint"`
	Bundle      json.RawMessage   `json:"bundle"`
	Manifests   []json.RawMessage `json:"manifests"`
	Signed      []commitment      `json:"signed,omitempty"`
}

type commitment struct {
	Type    string           `json:"type"`
	ScopeID pqcrypto.UUID    `json:"scope_id"`
	Epoch   pqcrypto.Counter `json:"epoch"`
	Digest  pqcrypto.HexID   `json:"digest"`
}

// commitment returns the signing commitment for (type, scope.id), or nil.
func (s *state) commitment(typ string, scope pqcrypto.UUID) *commitment {
	for i := range s.Signed {
		if c := &s.Signed[i]; c.Type == typ && c.ScopeID == scope {
			return c
		}
	}
	return nil
}

// loadTrust replays the persisted state through pqcrypto.Trust.
func (a *App) loadTrust() (*pqcrypto.Trust, error) {
	_, tr, err := a.load()
	return tr, err
}

func (a *App) load() (*state, *pqcrypto.Trust, error) {
	raw, err := os.ReadFile(filepath.Join(a.Home, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, ErrNotPinned
	}
	if err != nil {
		return nil, nil, err
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, nil, fmt.Errorf("kyguard-cli: %s is damaged: %w", stateFile, err)
	}
	tr, err := pqcrypto.NewTrust(s.Bundle, s.Fingerprint)
	if err != nil {
		return nil, nil, fmt.Errorf("kyguard-cli: persisted bundle no longer verifies: %w", err)
	}
	for _, m := range s.Manifests {
		if _, err := tr.Accept(m); err != nil {
			return nil, nil, fmt.Errorf("kyguard-cli: persisted manifest no longer verifies: %w", err)
		}
	}
	return &s, tr, nil
}

// save persists s with tr's records atomically (0600). It runs before the CLI signs or
// seals anything that depends on a newly accepted manifest. Callers hold the state lock.
func (a *App) save(s *state, tr *pqcrypto.Trust) error {
	s.Fingerprint, s.Manifests = tr.Fingerprint(), []json.RawMessage{}
	for _, r := range tr.Records() {
		s.Manifests = append(s.Manifests, r.Canonical)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.Home, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(a.Home, stateFile+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(a.Home, stateFile))
}

// lockState takes the exclusive interprocess lock on the trust state, waiting for any
// other kyguard-cli to finish, so each command's load, checks and save are one step.
func (a *App) lockState() (unlock func(), err error) {
	if err := os.MkdirAll(a.Home, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(a.Home, "trust.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFile(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("kyguard-cli: lock the trust state: %w", err)
	}
	return func() { f.Close() }, nil // closing the file releases the lock
}
