// Command kyguard-broker is the KyGuard Resource Broker (spec §2, §4.1): a Linux daemon
// inside the target network that connects outbound to the Control Plane.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/Busnes-app/kyguard-server/internal/broker"
)

const defaultDir = "/var/lib/kyguard-broker"

func main() {
	// No core dumps: a dump would carry DEKs and passwords from memory (§4.1).
	if err := disableCoreDumps(); err != nil {
		log.Fatalf("kyguard-broker: RLIMIT_CORE=0: %v", err)
	}
	dir := os.Getenv("KYGUARD_BROKER_DIR")
	if dir == "" {
		dir = defaultDir
	}
	app := &broker.App{Dir: dir, Out: os.Stdout, Nudges: make(chan struct{}, 1)}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cmd, args := "run", os.Args[1:]
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	var err error
	switch cmd {
	case "pair":
		fs := flag.NewFlagSet("pair", flag.ExitOnError)
		token := fs.String("token", "", "one-time pairing token from the Control Plane")
		fp := fs.String("bootstrap-fingerprint", "", "bootstrap_fingerprint, checked out of band")
		bundle := fs.String("bootstrap-bundle", "", "bootstrap bundle file, instead of the fingerprint")
		fs.Parse(args)
		err = app.Pair(ctx, *token, *fp, *bundle)
	case "run":
		err = app.Run(ctx)
	case "version":
		fmt.Println("kyguard-broker", broker.Version)
	default:
		err = fmt.Errorf("unknown command %q (pair, run, version)", cmd)
	}
	if err != nil {
		log.Fatalf("kyguard-broker: %v", err)
	}
}
