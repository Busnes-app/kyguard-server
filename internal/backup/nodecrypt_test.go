package backup_test

import (
	"path/filepath"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

// Nothing in the server opens a capsule sealed to the suite key, combines shares, or rebuilds
// the key from a seed. The one exemption is the restore command, with shares typed by an
// operator, and kyguard-cli's own user key files; the drill opens only a capsule sealed to a key it made and discarded, inside the lib.
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
	})
}
