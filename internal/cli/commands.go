package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
)

func newUUID() (pqcrypto.UUID, error) {
	u, err := uuid.NewV7()
	return pqcrypto.UUID(u.String()), err
}

// cmdInit runs the offline ceremony (§3.2 rule 2): custodian key files, the epoch-1
// CustodianSetManifest and RecoveryKeyManifest, signed by every custodian, and the bundle.
func (a *App) cmdInit(_ context.Context, args []string) error {
	fs := flags("init")
	recPub := fs.String("recovery-pub", "", "KyRecovery public key file (hex)")
	recT := fs.Int("recovery-threshold", 0, "Shamir threshold of the recovery key")
	recN := fs.Int("recovery-shares", 0, "Shamir share count of the recovery key")
	n := fs.Int("custodians", 3, "number of custodians N")
	m := fs.Int("threshold", 2, "custodian signatures required, M")
	escrow := fs.Bool("escrow-default", false, "default recovery escrow for new policy drafts")
	out := fs.String("out", "", "new directory for the bundle and custodian key files")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return errors.Join(err, errArgs(pos))
	}
	if err := required(fs, "recovery-pub", "recovery-threshold", "recovery-shares", "out"); err != nil {
		return err
	}
	if *n < 1 || *m < 1 || *m > *n {
		return errors.New("kyguard-cli init: need 1 <= threshold <= custodians")
	}
	raw, err := readFile(*recPub)
	if err != nil {
		return err
	}
	pubBytes, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return fmt.Errorf("kyguard-cli init: %s is not a hex public key", *recPub)
	}
	rpub, err := recoverykey.ParsePublicKey(pubBytes)
	if err != nil {
		return fmt.Errorf("kyguard-cli init: %w", err)
	}
	if err := mkdirNew(*out); err != nil {
		return err
	}
	dep, err := newUUID()
	if err != nil {
		return err
	}
	hdr := pqcrypto.Header{Type: pqcrypto.TypeCustodianSet, DeploymentID: dep, Epoch: 1,
		Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeDeployment, ID: dep}, SignerRole: pqcrypto.RoleCustodian}
	b := pqcrypto.Bundle{DeploymentID: dep}
	b.CustodianSet = pqcrypto.CustodianSetManifest{Header: hdr, Threshold: *m}
	hdr.Type = pqcrypto.TypeRecoveryKey
	b.RecoveryKey = pqcrypto.RecoveryKeyManifest{Header: hdr, RecoveryKeyID: pqcrypto.HexID(rpub.ID()),
		RecoveryPubkey: rpub.Bytes(), Threshold: *recT, TotalShares: *recN, EscrowDefaultEnabled: *escrow}
	var keys []*Key
	for i := 1; i <= *n; i++ {
		id, err := newUUID()
		if err != nil {
			return err
		}
		sk, err := pqcrypto.GenerateSigningKey()
		if err != nil {
			return err
		}
		k := &Key{Kind: KindCustodian, ID: id, Sign: sk}
		if k.SigKeyID, err = sk.Public().SigKeyID(); err != nil {
			return err
		}
		pass, err := a.Prompt.Passphrase(fmt.Sprintf("passphrase for custodian %d of %d", i, *n), true)
		if err != nil {
			return err
		}
		if err := writeKeyFile(filepath.Join(*out, fmt.Sprintf("custodian-%d.key", i)), pass, a.KDF, k); err != nil {
			return err
		}
		keys = append(keys, k)
		b.CustodianSet.Custodians = append(b.CustodianSet.Custodians, pqcrypto.Custodian{CustodianID: id, SigPub: sk.Public()})
	}
	for _, k := range keys {
		if err := pqcrypto.Sign(&b.CustodianSet, pqcrypto.RoleCustodian, k.Sign); err != nil {
			return err
		}
	}
	for _, k := range keys {
		if err := pqcrypto.Sign(&b.RecoveryKey, pqcrypto.RoleCustodian, k.Sign); err != nil {
			return err
		}
	}
	bundle, err := canonical.Marshal(&b)
	if err != nil {
		return err
	}
	fp, err := pqcrypto.BundleFingerprint(bundle)
	if err != nil {
		return err
	}
	// Prove the bundle verifies before anyone copies the fingerprint.
	if _, err := pqcrypto.NewTrust(bundle, fp.Hex()); err != nil {
		return fmt.Errorf("kyguard-cli init: the new bundle does not verify: %w", err)
	}
	if err := writeNew(filepath.Join(*out, "bundle.json"), bundle, 0o644); err != nil {
		return err
	}
	if *m == 1 && *n == 1 {
		a.printf("WARNING: a 1-of-1 custodian set: one lost or stolen key file decides everything.\n")
	}
	a.printf("deployment_id          %s\ncustodians             %d of %d\n", dep, *m, *n)
	for i, k := range keys {
		a.printf("custodian %-12d %s  sig_key_id %s\n", i+1, k.ID, k.SigKeyID)
	}
	a.printf("recovery_key_id        %s (threshold %d of %d)\n", rpub.ID(), *recT, *recN)
	a.printf("bootstrap_fingerprint  %s\n", fp.Hex())
	return nil
}

// cmdTrust pins a bootstrap fingerprint and verifies the bundle against it (§3.2 rule 3).
// Replacing an existing pin needs --replace: it is the custodian-quorum-loss path (rule 5).
func (a *App) cmdTrust(ctx context.Context, args []string) error {
	fs := flags("trust")
	bundlePath := fs.String("bundle", "", "bundle file (default: fetch from the Control Plane)")
	replace := fs.Bool("replace", false, "replace an existing, different pin")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: kyguard-cli trust <fingerprint> [--bundle FILE] [--replace]")
	}
	fp := pqcrypto.HexID(strings.ToLower(strings.TrimSpace(pos[0])))
	if !fp.Valid() {
		return errors.New("kyguard-cli trust: the fingerprint is 64 hex characters")
	}
	if cur, err := a.loadTrust(); err == nil && cur.Fingerprint() != fp && !*replace {
		return fmt.Errorf("kyguard-cli trust: already pinned to %s; pass --replace only after custodian quorum loss", cur.Fingerprint())
	} else if err != nil && !errors.Is(err, ErrNotPinned) {
		return err
	}
	var bundle []byte
	switch {
	case *bundlePath != "":
		bundle, err = readFile(*bundlePath)
	case a.Client != nil:
		bundle, err = a.Client.Bundle(ctx)
	default:
		err = ErrNoClient
	}
	if err != nil {
		return err
	}
	tr, err := pqcrypto.NewTrust(bundle, fp)
	if err != nil {
		return fmt.Errorf("kyguard-cli trust: %w", err)
	}
	bundle, err = canonical.Canonicalize(bundle)
	if err != nil {
		return err
	}
	if err := a.saveTrust(bundle, tr); err != nil {
		return err
	}
	cs := tr.CustodianSet()
	a.printf("pinned %s\ndeployment_id %s, custodians %d of %d\n", fp, tr.DeploymentID(), cs.Threshold, len(cs.Custodians))
	return nil
}

// cmdImport verifies manifests against the pin and records their high-water marks. Without
// a pin it refuses everything; a lower epoch or same-epoch fork is refused (§3.7).
func (a *App) cmdImport(ctx context.Context, args []string) error {
	fs := flags("import")
	files, err := parse(fs, args)
	if err != nil {
		return err
	}
	tr, err := a.loadTrust()
	if err != nil {
		return err
	}
	var ms [][]byte
	if len(files) == 0 {
		if a.Client == nil {
			return ErrNoClient
		}
		if ms, err = a.Client.Manifests(ctx); err != nil {
			return err
		}
	}
	for _, p := range files {
		b, err := readFile(p)
		if err != nil {
			return err
		}
		ms = append(ms, b)
	}
	for i, m := range ms {
		r, err := tr.Accept(m)
		if errors.Is(err, pqcrypto.ErrEquivocation) {
			return fmt.Errorf("kyguard-cli import: ALERT: equivocation in manifest %d: %w", i+1, err)
		}
		if err != nil {
			return fmt.Errorf("kyguard-cli import: manifest %d: %w", i+1, err)
		}
		a.printf("accepted %s %s epoch %s digest %s\n", r.Type, r.ScopeID, r.Epoch, r.Digest.Hex())
	}
	bundle, err := a.persistedBundle()
	if err != nil {
		return err
	}
	return a.saveTrust(bundle, tr)
}

// cmdEnroll generates a user's signing and X-Wing keys, writes the key file and a
// self-signed KeyEnrollmentManifest draft for Custodian signing (§3.2 rule 4, §3.3).
func (a *App) cmdEnroll(ctx context.Context, args []string) error {
	fs := flags("enroll")
	principal := fs.String("principal-id", "", "your principal ID (users.id)")
	issuer := fs.String("issuer", "", "your SSO issuer")
	subject := fs.String("subject", "", "your SSO subject")
	keyOut := fs.String("key-out", "", "new key file")
	draftOut := fs.String("draft-out", "", "write the draft here instead of submitting it")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return errors.Join(err, errArgs(pos))
	}
	if err := required(fs, "principal-id", "issuer", "subject", "key-out"); err != nil {
		return err
	}
	pid := pqcrypto.UUID(*principal)
	if !pid.Valid() {
		return errors.New("kyguard-cli enroll: --principal-id is a lowercase UUID")
	}
	tr, err := a.loadTrust()
	if err != nil {
		return err
	}
	if tr.Enrollment(pid) != nil {
		return errors.New("kyguard-cli enroll: this principal is already enrolled; key rotation is a later step")
	}
	sk, err := pqcrypto.GenerateSigningKey()
	if err != nil {
		return err
	}
	enc, err := recoverykey.Generate()
	if err != nil {
		return err
	}
	k := &Key{Kind: KindUser, ID: pid, Sign: sk, Enc: enc}
	if k.SigKeyID, err = sk.Public().SigKeyID(); err != nil {
		return err
	}
	encID := pqcrypto.HexID(enc.Public().ID())
	m := &pqcrypto.KeyEnrollmentManifest{
		Header: pqcrypto.Header{Type: pqcrypto.TypeKeyEnrollment, DeploymentID: tr.DeploymentID(), Epoch: 1,
			Scope: pqcrypto.Scope{Kind: pqcrypto.ScopePrincipal, ID: pid}, SignerRole: pqcrypto.RoleCustodian},
		PrincipalID: pid, Issuer: *issuer, Subject: *subject,
		Keys: []pqcrypto.EnrolledKey{{EncPub: enc.Public().Bytes(), EncKeyID: encID, SigPub: sk.Public(), SigKeyID: k.SigKeyID, Status: pqcrypto.StatusActive}},
	}
	if _, _, err := pqcrypto.DecodeManifest(mustCanon(m)); err != nil {
		return fmt.Errorf("kyguard-cli enroll: %w", err)
	}
	if err := pqcrypto.Sign(m, pqcrypto.RoleUser, sk); err != nil {
		return err
	}
	draft, err := canonical.Marshal(m)
	if err != nil {
		return err
	}
	pass, err := a.Prompt.Passphrase("passphrase for your new key file", true)
	if err != nil {
		return err
	}
	if err := writeKeyFile(*keyOut, pass, a.KDF, k); err != nil {
		return err
	}
	switch {
	case *draftOut != "":
		err = writeNew(*draftOut, draft, 0o644)
	case a.Client != nil:
		var id string
		if id, err = a.Client.SubmitDraft(ctx, draft); err == nil {
			a.printf("submitted draft %s\n", id)
		}
	default:
		err = ErrNoClient
	}
	if err != nil {
		return err
	}
	a.printf("Give these to a Custodian over a channel the Control Plane does not control:\n")
	a.printf("issuer        %s\nsubject       %s\nprincipal_id  %s\nsig_key_id    %s\nenc_key_id    %s\n", *issuer, *subject, pid, k.SigKeyID, encID)
	return nil
}

func mustCanon(v any) []byte {
	b, err := canonical.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// cmdSign shows a manifest draft decoded and applies the Custodian signature (§3.2 rule 4).
// It refuses a draft for another deployment, from a key outside the current custodian set,
// or below the high-water mark: a lower epoch, or the same epoch with another digest.
func (a *App) cmdSign(ctx context.Context, args []string) error {
	fs := flags("sign")
	keyPath := fs.String("key", "", "your custodian key file")
	draftPath := fs.String("draft", "", "draft manifest file")
	draftID := fs.String("draft-id", "", "draft ID on the Control Plane")
	targetPath := fs.String("target", "", "target descriptor file (managed policies)")
	out := fs.String("out", "", "write the signed manifest here (with --draft)")
	yes := fs.Bool("yes", false, "sign without the confirmation prompt")
	if pos, err := parse(fs, args); err != nil || len(pos) > 0 {
		return errors.Join(err, errArgs(pos))
	}
	if err := required(fs, "key"); err != nil {
		return err
	}
	tr, err := a.loadTrust()
	if err != nil {
		return err
	}
	var d *Draft
	switch {
	case *draftPath != "":
		if *out == "" {
			return errors.New("kyguard-cli sign: --draft needs --out")
		}
		d = &Draft{}
		if d.Object, err = readFile(*draftPath); err != nil {
			return err
		}
	case *draftID != "" && a.Client != nil:
		if d, err = a.Client.Draft(ctx, *draftID); err != nil {
			return err
		}
	case *draftID != "":
		return ErrNoClient
	default:
		return errors.New("kyguard-cli sign: pass --draft FILE or --draft-id ID")
	}
	if *targetPath != "" {
		if d.Target, err = readFile(*targetPath); err != nil {
			return err
		}
	}
	m, dg, err := pqcrypto.DecodeManifest(d.Object)
	if err != nil {
		return fmt.Errorf("kyguard-cli sign: %w", err)
	}
	h := pqcrypto.HeaderOf(m)
	if h.DeploymentID != tr.DeploymentID() {
		return fmt.Errorf("kyguard-cli sign: %w", pqcrypto.ErrDeployment)
	}
	if r := tr.Lookup(h.Type, h.Scope.ID); r != nil {
		if h.Epoch < r.Epoch {
			return fmt.Errorf("kyguard-cli sign: epoch %s is below the verified epoch %s: %w", h.Epoch, r.Epoch, pqcrypto.ErrRollback)
		}
		if h.Epoch == r.Epoch && dg != r.Digest {
			return fmt.Errorf("kyguard-cli sign: ALERT: epoch %s already verified with another digest: %w", h.Epoch, pqcrypto.ErrEquivocation)
		}
	}
	if err := a.show(tr, m, dg, d); err != nil {
		return err
	}
	pass, err := a.Prompt.Passphrase("passphrase for "+*keyPath, false)
	if err != nil {
		return err
	}
	k, err := openKeyFile(*keyPath, pass, KindCustodian)
	if err != nil {
		return err
	}
	if !inCustodianSet(tr, k) {
		return fmt.Errorf("kyguard-cli sign: %s is not in the current custodian set: %w", k.SigKeyID, pqcrypto.ErrUnknownKey)
	}
	if !*yes {
		ok, err := a.Prompt.Confirm(fmt.Sprintf("Sign %s %s epoch %s digest %s?", h.Type, h.Scope.ID, h.Epoch, dg.Hex()))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("kyguard-cli sign: not signed")
		}
	}
	if err := pqcrypto.Sign(m, pqcrypto.RoleCustodian, k.Sign); err != nil {
		return err
	}
	signed, err := canonical.Marshal(m)
	if err != nil {
		return err
	}
	// A manifest that is now complete is accepted locally, raising the high-water mark.
	if r, err := tr.Accept(signed); err == nil {
		bundle, err := a.persistedBundle()
		if err != nil {
			return err
		}
		if err := a.saveTrust(bundle, tr); err != nil {
			return err
		}
		a.printf("complete: accepted %s epoch %s\n", r.Type, r.Epoch)
	} else {
		a.printf("signed; not yet complete (%v)\n", err)
	}
	if *out != "" {
		return writeNew(*out, signed, 0o644)
	}
	return a.Client.SubmitSignature(ctx, *draftID, signed)
}

func inCustodianSet(tr *pqcrypto.Trust, k *Key) bool {
	for _, c := range tr.CustodianSet().Custodians {
		if id, _ := c.SigPub.SigKeyID(); id == k.SigKeyID && c.CustodianID == k.ID {
			return true
		}
	}
	return false
}

// mkdirNew creates an owner-only directory that must not exist yet.
func mkdirNew(path string) error {
	return os.Mkdir(path, 0o700)
}

func errArgs(pos []string) error {
	if len(pos) == 0 {
		return nil
	}
	return fmt.Errorf("kyguard-cli: unexpected arguments %q", pos)
}
