// Package cli is kyguard-cli (spec §2, §3.2): offline deployment init, trust pinning,
// user key enrollment and Custodian signing. It handles every key and signature on the
// user side; the Control Plane is reached only through Client.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/Busnes-app/ky-primitives/password"
)

// Draft is an unsigned or partly signed object the Control Plane relays for signing.
// Labels and Target come from the Control Plane and are untrusted: labels are shown marked
// unverified, and a target descriptor is shown only when its digest matches the policy's.
type Draft struct {
	Object []byte
	Target []byte
	Labels map[string]string
}

// Client is the Control Plane's draft and manifest API. `kyguard-cli login` (§7.6) builds
// the session-authenticated implementation; until it exists every command also takes files.
type Client interface {
	Bundle(ctx context.Context) ([]byte, error)
	Manifests(ctx context.Context) ([][]byte, error)
	Draft(ctx context.Context, id string) (*Draft, error)
	SubmitDraft(ctx context.Context, object []byte) (id string, err error)
	SubmitSignature(ctx context.Context, id string, signed []byte) error
}

// ErrNoClient reports a command that needs the Control Plane when none is configured.
var ErrNoClient = errors.New("kyguard-cli: no Control Plane session; pass the file instead (login arrives with §7.6)")

// Prompter asks the operator for passphrases and confirmations.
type Prompter interface {
	Passphrase(label string, confirm bool) (string, error)
	Confirm(question string) (bool, error)
}

// App holds the CLI's environment.
type App struct {
	Home   string // state directory (trust.json)
	Out    io.Writer
	Prompt Prompter
	Client Client          // nil when offline
	KDF    password.Params // Argon2id cost for new key files
}

// Run executes one command.
func (a *App) Run(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	cmds := map[string]func(context.Context, []string) error{
		"init": a.cmdInit, "trust": a.cmdTrust, "import": a.cmdImport, "enroll": a.cmdEnroll, "sign": a.cmdSign,
	}
	cmd, ok := cmds[args[0]]
	if !ok {
		return fmt.Errorf("kyguard-cli: unknown command %q\n%s", args[0], usage)
	}
	return cmd(ctx, args[1:])
}

const usage = `usage: kyguard-cli <command> [flags]
  init     create the deployment bootstrap bundle and custodian key files (offline)
  trust    pin the bootstrap fingerprint and verify the bundle
  import   verify and record manifests against the pinned bundle
  enroll   generate your keys and a self-signed key enrollment draft
  sign     review a manifest draft and apply your Custodian signature`

func flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("kyguard-cli "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

// parse parses flags anywhere among the arguments and returns the positional ones.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func (a *App) printf(format string, args ...any) { fmt.Fprintf(a.Out, format, args...) }

// readFile reads a bounded input file.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	if err != nil {
		return nil, err
	}
	if len(b) > 8<<20 {
		return nil, fmt.Errorf("kyguard-cli: %s is larger than 8 MiB", path)
	}
	return b, nil
}

// writeNew writes a file that must not exist yet.
func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func required(fs *flag.FlagSet, names ...string) error {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	var missing []string
	for _, n := range names {
		if !set[n] {
			missing = append(missing, "--"+n)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s: missing %s", fs.Name(), strings.Join(missing, ", "))
	}
	return nil
}
