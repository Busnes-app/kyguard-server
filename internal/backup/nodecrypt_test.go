package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

// Nothing in the server opens a capsule sealed to the suite key, combines shares, or rebuilds
// the key from a seed. The one exemption is the restore command, with shares typed by an
// operator, kyguard-cli's own user key files and kyguard-broker's own key file; the drill opens only a capsule sealed to a key it made and discarded, inside the lib.
func TestNothingInTheServerDecrypts(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	guardtest.NoDecryptOutside(t, root, map[string][]string{
		filepath.Join("cmd", "server", "main.go"): {"restore"},
		// kyguard-cli (not the server) rebuilds a user's own X-Wing key from that user's
		// passphrase-sealed key file; it never touches the suite recovery key.
		filepath.Join("internal", "cli", "keyfile.go"): {"openKeyFile"},
		// kyguard-broker (not the server) rebuilds its own X-Wing key from its 0600 key file
		// to unwrap DEKs sealed to it (§3.5, §4.1).
		filepath.Join("internal", "broker", "keys.go"): {"openKeys"},
	})
}
