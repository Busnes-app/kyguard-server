package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// pairingIntentGrace is how old a pending pairing intent must be before startup declares
// its outcome unknown; a replica may still be writing a younger one's response.
const pairingIntentGrace = 2 * time.Minute

// runGuardInit is `kyguard-server init`: it creates the internal broker CA (§3.2 rule 2).
// The listener leaf is issued from it at every start (§9.4). It creates no signing key.
func runGuardInit(cfg *config.Config, out io.Writer) error {
	ca, err := brokerproto.CreateCA(cfg.Database.DataDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "broker CA created in %s\nbroker_ca_sha256  %s\n", cfg.Database.DataDir, ca.SHA256())
	return nil
}

// runImportBundle is `kyguard-server import-bundle --bundle <file> --fingerprint <hex>`: the
// bundle is verified against the fingerprint the custodians printed (§3.2 rule 2) and stored.
func runImportBundle(ctx context.Context, st store.Store, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import-bundle", flag.ContinueOnError)
	path := fs.String("bundle", "", "bootstrap bundle file from kyguard-cli init")
	fp := fs.String("fingerprint", "", "bootstrap_fingerprint printed by kyguard-cli init")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || *fp == "" {
		return errors.New("import-bundle: --bundle and --fingerprint are required")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	tr, err := pqcrypto.NewTrust(raw, pqcrypto.HexID(strings.ToLower(strings.TrimSpace(*fp))))
	if err != nil {
		return fmt.Errorf("import-bundle: bundle does not verify against the fingerprint: %w", err)
	}
	canon, err := canonicalBundle(raw)
	if err != nil {
		return err
	}
	err = st.Guard().ImportBundle(ctx, &store.BootstrapBundle{DeploymentID: string(tr.DeploymentID()), Fingerprint: string(tr.Fingerprint()), Bundle: canon}, "host")
	if errors.Is(err, store.ErrAlreadyExists) {
		return errors.New("import-bundle: a different bundle is already imported")
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "bundle imported\ndeployment_id          %s\nbootstrap_fingerprint  %s\n", tr.DeploymentID(), tr.Fingerprint())
	return nil
}

func canonicalBundle(raw []byte) ([]byte, error) {
	var b pqcrypto.Bundle
	return canonical.Decode(raw, &b)
}

// checkBrokerCA refuses a start whose broker CA is not the one paired brokers pinned (a
// restore with the wrong CA, §9.4 rule 3), and settles pairing intents a stopped process
// left pending (§9.3).
func checkBrokerCA(ctx context.Context, cfg *config.Config, st store.Store) error {
	pinned, err := st.Guard().BrokerCAHashes(ctx)
	if err != nil {
		return err
	}
	ca, err := brokerproto.LoadCA(cfg.Database.DataDir)
	switch {
	case errors.Is(err, fs.ErrNotExist) && len(pinned) == 0:
	case err != nil:
		return fmt.Errorf("broker CA: %w", err)
	default:
		for _, h := range pinned {
			if h != string(ca.SHA256()) {
				return fmt.Errorf("broker CA %s is not the CA paired brokers pinned (%s); restore data/%s and data/%s from the same capsule", ca.SHA256(), h, brokerproto.CACertFile, brokerproto.CAKeyFile)
			}
		}
	}
	return settlePairingIntents(ctx, st, pairingIntentGrace)
}

// settlePairingIntents marks pairing intents pending for longer than grace outcome_unknown.
func settlePairingIntents(ctx context.Context, st store.Store, grace time.Duration) error {
	n, err := st.Guard().ExpirePendingIntents(ctx, "pairing", time.Now().Add(-grace))
	if err != nil {
		return err
	}
	if n > 0 {
		log.Printf("[BROKER] %d pairing claims ended with their response undelivered: outcome_unknown, an operator must reconcile them", n)
	}
	return nil
}

// settleLoop repeats the settlement every tick, so an intent too young at startup (or left
// by a replica that stopped) is settled once its grace has passed.
func settleLoop(ctx context.Context, st store.Store, tick, grace time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := settlePairingIntents(ctx, st, grace); err != nil && ctx.Err() == nil {
				log.Printf("[BROKER] settling pairing intents: %v", err)
			}
		}
	}
}

// startBrokerListener serves /broker/v1/* on KY_BROKER_LISTEN with a fresh leaf for
// KY_BROKER_HOSTNAME. It returns nil when the broker listener is not configured.
func startBrokerListener(cfg *config.Config, srv *api.Server) (*http.Server, error) {
	l := srv.BrokerListener()
	if l == nil {
		log.Printf("[BROKER] broker listener disabled: run kyguard-server init and set KY_BROKER_HOSTNAME")
		return nil, nil
	}
	leaf, err := l.CA.ListenerCert(cfg.Broker.Hostname)
	if err != nil {
		return nil, err
	}
	hs := &http.Server{
		Addr:              cfg.Broker.Listen,
		Handler:           l.Handler(),
		TLSConfig:         brokerproto.ServerTLS(l.CA, leaf),
		ReadHeaderTimeout: 10 * time.Second,
		// The channel is long-lived; WebSocket reads carry their own context.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	ln, err := tls.Listen("tcp", cfg.Broker.Listen, hs.TLSConfig)
	if err != nil {
		return nil, err
	}
	go func() {
		log.Printf("[BROKER] broker listener on %s for %s", cfg.Broker.Listen, cfg.Broker.Hostname)
		if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("broker listener: %v", err)
		}
	}()
	return hs, nil
}

func runGuardCommand(name string, args []string) error {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		return err
	}
	if name == "init" {
		return runGuardInit(cfg, os.Stdout)
	}
	ctx := context.Background()
	st, err := store.Open(ctx, cfg.Database)
	if err != nil {
		return err
	}
	defer st.Close()
	return runImportBundle(ctx, st, args, os.Stdout)
}
