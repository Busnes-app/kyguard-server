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
// in order. Replaying it rebuilds the high-water mark per (type, scope.id).
type state struct {
	Fingerprint pqcrypto.HexID    `json:"fingerprint"`
	Bundle      json.RawMessage   `json:"bundle"`
	Manifests   []json.RawMessage `json:"manifests"`
}

// loadTrust replays the persisted state through pqcrypto.Trust.
func (a *App) loadTrust() (*pqcrypto.Trust, error) {
	raw, err := os.ReadFile(filepath.Join(a.Home, stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotPinned
	}
	if err != nil {
		return nil, err
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, fmt.Errorf("kyguard-cli: %s is damaged: %w", stateFile, err)
	}
	tr, err := pqcrypto.NewTrust(s.Bundle, s.Fingerprint)
	if err != nil {
		return nil, fmt.Errorf("kyguard-cli: persisted bundle no longer verifies: %w", err)
	}
	for _, m := range s.Manifests {
		if _, err := tr.Accept(m); err != nil {
			return nil, fmt.Errorf("kyguard-cli: persisted manifest no longer verifies: %w", err)
		}
	}
	return tr, nil
}

// saveTrust persists tr atomically (0600). It runs before the CLI signs or seals anything
// that depends on a newly accepted manifest.
func (a *App) saveTrust(bundle []byte, tr *pqcrypto.Trust) error {
	s := state{Fingerprint: tr.Fingerprint(), Bundle: bundle, Manifests: []json.RawMessage{}}
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

// persistedBundle returns the bundle bytes of the current state.
func (a *App) persistedBundle() ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(a.Home, stateFile))
	if err != nil {
		return nil, ErrNotPinned
	}
	var s state
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, err
	}
	return s.Bundle, nil
}
