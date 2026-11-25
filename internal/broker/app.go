package broker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

// App is kyguard-broker on one host; Dir holds the key file and the journal.
type App struct {
	Dir string
	Out io.Writer
	// Nudges receives one value per Control Plane nudge; the scheduler drains it. A nudge
	// carries no authority and no content (§3.4).
	Nudges chan struct{}
}

// Pair is `kyguard-broker pair --token <t> --bootstrap-fingerprint <hex>` (or
// --bootstrap-bundle <file>), §4.1 pairing steps 2–4.
func (a *App) Pair(ctx context.Context, token, fingerprint, bundleFile string) error {
	tok, err := brokerproto.ParseToken(token)
	if err != nil {
		return err
	}
	fp, err := pinnedFingerprint(fingerprint, bundleFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(a.Dir, 0o700); err != nil {
		return err
	}
	j, err := OpenJournal(a.Dir)
	if err != nil {
		return err
	}
	defer j.Close()
	if _, err := j.Identity(); err == nil {
		return errors.New("broker: already paired")
	} else if !errors.Is(err, ErrNotPaired) {
		return err
	}
	// Keys from an earlier attempt that never paired were never listed anywhere; reuse them.
	k, err := LoadKeys(a.Dir)
	if errors.Is(err, os.ErrNotExist) {
		k, err = CreateKeys(a.Dir)
	}
	if err != nil {
		return err
	}
	p, err := brokerproto.Pair(ctx, tok, fp, k.TLS, k.Sig.Public(), k.Enc.Public().Bytes())
	if err != nil {
		return err
	}
	if err := j.SavePairing(&Identity{BrokerID: p.BrokerID, Cert: p.Cert, CACert: p.CACert, ListenerURL: tok.URL, Bundle: p.Bundle, Fingerprint: fp}); err != nil {
		return err
	}
	fmt.Fprintf(a.Out, "Paired. Give these to the Custodians through a channel independent of the Control Plane:\n"+
		"broker_id         %s\nsig_key_id        %s\nenc_key_id        %s\ncert_sha256       %s\n"+
		"The broker does no work until a Custodian-signed pool manifest lists it as active.\n",
		p.BrokerID, k.SigKeyID(), k.EncKeyID(), brokerproto.CertSHA256(p.Cert.Raw))
	return nil
}

func pinnedFingerprint(fingerprint, bundleFile string) (pqcrypto.HexID, error) {
	switch {
	case (fingerprint == "") == (bundleFile == ""):
		return "", errors.New("broker: give exactly one of --bootstrap-fingerprint and --bootstrap-bundle")
	case fingerprint != "":
		fp := pqcrypto.HexID(strings.ToLower(strings.TrimSpace(fingerprint)))
		if !fp.Valid() {
			return "", errors.New("broker: --bootstrap-fingerprint must be 64 hex characters")
		}
		return fp, nil
	}
	raw, err := os.ReadFile(filepath.Clean(bundleFile))
	if err != nil {
		return "", err
	}
	d, err := pqcrypto.BundleFingerprint(raw)
	if err != nil {
		return "", err
	}
	return d.Hex(), nil
}

// Run is the daemon: it holds the control channel open, reconnecting with backoff.
func (a *App) Run(ctx context.Context) error {
	j, err := OpenJournal(a.Dir)
	if err != nil {
		return err
	}
	defer j.Close()
	id, err := j.Identity()
	if err != nil {
		return err
	}
	k, err := LoadKeys(a.Dir)
	if err != nil {
		return err
	}
	cert := k.ClientCert(id.Cert)
	wait := time.Second
	for {
		c, err := brokerproto.Dial(ctx, id.ListenerURL, id.CACert, cert)
		if err == nil {
			log.Printf("[BROKER] channel open as %s", id.BrokerID)
			wait = time.Second
			err = a.serve(ctx, c)
		}
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("[BROKER] channel: %v; retrying in %s", err, wait)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
		wait = min(2*wait, time.Minute)
	}
}

func (a *App) serve(ctx context.Context, c *websocket.Conn) error {
	defer c.CloseNow()
	for {
		_, data, err := c.Read(ctx)
		if err != nil {
			return err
		}
		var m brokerproto.Message
		if err := json.Unmarshal(data, &m); err != nil || m.V != 1 {
			return errors.New("unsupported message from the Control Plane")
		}
		switch m.Type {
		case brokerproto.MsgNudge:
			select {
			case a.Nudges <- struct{}{}:
			default: // one pending nudge is enough
			}
		default:
			log.Printf("[BROKER] ignoring message type %q", m.Type)
		}
	}
}
