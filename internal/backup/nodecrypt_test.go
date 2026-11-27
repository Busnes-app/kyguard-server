package backup_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient/guardtest"
)

// Nothing in the server opens a capsule sealed to the suite key, combines shares, or rebuilds
// the key from a seed. The one exemption is the restore command, with shares typed by an
// operator. The offline utility, broker and independent browser client also rebuild
// their own X-Wing keys for work addressed to them.
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
		// The trusted browser opens user keys in WASM. The server handles only the
		// public envelope shape in pqcrypto.
		filepath.Join("internal", "vaultclient", "keys.go"): {"OpenKey"},
	})
}

// Keep the browser exception above outside the dependency graph of the server binary.
func TestServerDoesNotLinkBrowserKeyOpening(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "../../cmd/server")
	raw, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, dep := range strings.Fields(string(raw)) {
		if dep == "github.com/Busnes-app/kyguard-server/internal/vaultclient" {
			t.Fatal("server depends on the browser encryption and key opening implementation")
		}
	}
}
