// Command kyguard-cli is KyGuard's offline and user-side tool (spec §2): deployment init,
// trust pinning, key enrollment and Custodian signing.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busnes-app/ky-primitives/password"
	"golang.org/x/term"

	"github.com/Busnes-app/kyguard-server/internal/cli"
)

func main() {
	home := os.Getenv("KYGUARD_HOME")
	if home == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		home = filepath.Join(dir, "kyguard")
	}
	app := &cli.App{Home: home, Out: os.Stdout, Prompt: &terminal{in: bufio.NewReader(os.Stdin)}, KDF: password.DefaultParams()}
	if err := app.Run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// terminal prompts on stderr and reads without echo from a terminal, or a line from a pipe.
type terminal struct{ in *bufio.Reader }

func (t *terminal) line(prompt string, secret bool) (string, error) {
	fmt.Fprint(os.Stderr, prompt+": ")
	if secret && term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	s, err := t.in.ReadString('\n')
	if err != nil && s == "" {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

func (t *terminal) Passphrase(label string, confirm bool) (string, error) {
	p, err := t.line(label, true)
	if err != nil || !confirm {
		return p, err
	}
	again, err := t.line("repeat "+label, true)
	if err != nil {
		return "", err
	}
	if again != p {
		return "", errors.New("kyguard-cli: passphrases differ")
	}
	return p, nil
}

func (t *terminal) Confirm(q string) (bool, error) {
	a, err := t.line(q+" type yes", false)
	return a == "yes", err
}
