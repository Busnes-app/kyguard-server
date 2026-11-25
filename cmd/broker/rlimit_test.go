//go:build unix

package main

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// §4.1: the broker runs with RLIMIT_CORE=0, soft and hard.
func TestDisableCoreDumps(t *testing.T) {
	if err := disableCoreDumps(); err != nil {
		t.Fatal(err)
	}
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil {
		t.Fatal(err)
	}
	if l.Cur != 0 || l.Max != 0 {
		t.Fatalf("RLIMIT_CORE = %+v", l)
	}
}

// unitService returns the [Service] lines of the shipped unit.
func unitService(t *testing.T) []string {
	f, err := os.Open("../../deploy/broker/kyguard-broker.service")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	in := false
	for s := bufio.NewScanner(f); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		switch {
		case strings.HasPrefix(line, "["):
			in = line == "[Service]"
		case in && line != "" && !strings.HasPrefix(line, "#"):
			out = append(out, line)
		}
	}
	return out
}

// The startup step runs under the unit's own sandbox and syscall filter, through a user
// systemd manager. User=/Group= (no user switch there), CapabilityBoundingSet= (an
// unprivileged manager can't drop it, and its process holds no capabilities anyway) and
// ExecStart=/Restart= are dropped;
// a copy of the test binary runs from a bound /var/tmp directory. Skipped
// where no user manager runs (CI containers); run it on a systemd host.
func TestDisableCoreDumpsUnderTheUnit(t *testing.T) {
	if os.Getenv("KYGUARD_RLIMIT_CHILD") == "1" {
		if err := disableCoreDumps(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if _, err := exec.LookPath("systemd-run"); err != nil {
		t.Skip("no systemd-run")
	}
	if err := exec.Command("systemctl", "--user", "show-environment").Run(); err != nil {
		t.Skip("no systemd user manager")
	}
	// ProtectHome hides a test binary under $HOME even when bound, so run a copy from
	// /var/tmp (which PrivateTmp hides until bound back in).
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/var/tmp", "kyguard-broker-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	bin := filepath.Join(dir, "broker.test")
	if err := exec.Command("cp", self, bin).Run(); err != nil {
		t.Fatal(err)
	}
	args := []string{"--user", "--wait", "--pipe", "--quiet"}
	for _, line := range unitService(t) {
		switch strings.SplitN(line, "=", 2)[0] {
		case "User", "Group", "CapabilityBoundingSet", "ExecStart", "Restart", "RestartSec", "Type":
			continue
		}
		args = append(args, "-p", line)
	}
	args = append(args, "-p", "BindReadOnlyPaths="+dir,
		"-p", "Environment=KYGUARD_RLIMIT_CHILD=1",
		bin, "-test.run=^TestDisableCoreDumpsUnderTheUnit$", "-test.v")
	out, err := exec.Command("systemd-run", args...).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS") {
		t.Fatalf("under the unit: %v\n%s", err, out)
	}
}
