package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Busnes-app/ky-primitives/keyfile"
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
	s, cur, err := a.load()
	switch {
	case err == nil && cur.Fingerprint() == fp:
		// Re-pinning the same root keeps every accepted manifest and commitment.
		a.printf("already pinned %s\n", fp)
		return nil
	case err == nil && !*replace:
		return fmt.Errorf("kyguard-cli trust: already pinned to %s; pass --replace only after custodian quorum loss", cur.Fingerprint())
	case errors.Is(err, ErrNotPinned):
		s = &state{}
	case err != nil:
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
	// A replaced root keeps this CLI's signing commitments: they only ever refuse more.
	s.Bundle = bundle
	if err := a.save(s, tr); err != nil {
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
	s, tr, err := a.load()
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
	return a.save(s, tr)
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
	// Check every destination before any key exists, so a failure strands no key file.
	draftPath := *draftOut
	if draftPath == "" {
		if a.Client == nil {
			return ErrNoClient
		}
		draftPath = *keyOut + ".draft.json"
	}
	if err := checkNewFiles(*keyOut, draftPath); err != nil {
		return fmt.Errorf("kyguard-cli enroll: %w", err)
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
	sealed, err := sealKeyFile(pass, a.KDF, k)
	if err != nil {
		return err
	}
	// The key and its draft appear together or not at all.
	if err := createPair(*keyOut, sealed, draftPath, draft); err != nil {
		return fmt.Errorf("kyguard-cli enroll: %w", err)
	}
	if *draftOut == "" {
		id, err := a.Client.SubmitDraft(ctx, draft)
		if err != nil {
			return fmt.Errorf("kyguard-cli enroll: the draft is saved at %s; submitting it failed: %w", draftPath, err)
		}
		a.printf("submitted draft %s\n", id)
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
	s, tr, err := a.load()
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
	// This CLI's own earlier signatures bind it too, even below quorum.
	if c := s.commitment(h.Type, h.Scope.ID); c != nil {
		if h.Epoch < c.Epoch {
			return fmt.Errorf("kyguard-cli sign: epoch %s is below epoch %s already signed here: %w", h.Epoch, c.Epoch, pqcrypto.ErrRollback)
		}
		if h.Epoch == c.Epoch && dg.Hex() != c.Digest {
			return fmt.Errorf("kyguard-cli sign: ALERT: epoch %s already signed here with another digest: %w", h.Epoch, pqcrypto.ErrEquivocation)
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
	// Every signature on the draft must verify, and so must the successor rules: only a
	// short quorum may remain. Otherwise the signature is never released.
	complete := tr.Check(signed)
	if complete != nil && !errors.Is(complete, pqcrypto.ErrThreshold) {
		return fmt.Errorf("kyguard-cli sign: the draft can never be accepted: %w", complete)
	}
	// Persist the commitment before the signature leaves, so no later draft can make this
	// CLI sign a lower epoch or a fork of it.
	if c := s.commitment(h.Type, h.Scope.ID); c != nil {
		c.Epoch, c.Digest = h.Epoch, dg.Hex()
	} else {
		s.Signed = append(s.Signed, commitment{h.Type, h.Scope.ID, h.Epoch, dg.Hex()})
	}
	if err := a.save(s, tr); err != nil {
		return err
	}
	// Deliver next: the local high-water mark rises only once the signature is out, so a
	// failed write never activates a manifest nobody else has.
	if *out != "" {
		err = writeNew(*out, signed, 0o644)
	} else {
		err = a.Client.SubmitSignature(ctx, *draftID, signed)
	}
	if err != nil {
		return err
	}
	if complete != nil {
		a.printf("signed; not yet complete: more custodian signatures are needed\n")
		return nil
	}
	r, err := tr.Accept(signed)
	if err != nil {
		return err
	}
	if err := a.save(s, tr); err != nil {
		return err
	}
	a.printf("complete: accepted %s epoch %s\n", r.Type, r.Epoch)
	return nil
}

func inCustodianSet(tr *pqcrypto.Trust, k *Key) bool {
	for _, c := range tr.CustodianSet().Custodians {
		if id, _ := c.SigPub.SigKeyID(); id == k.SigKeyID && c.CustodianID == k.ID {
			return true
		}
	}
	return false
}

// checkNewFiles requires two distinct paths that do not exist yet, in existing directories.
func checkNewFiles(a, b string) error {
	var dirs [2]os.FileInfo
	for i, p := range []string{a, b} {
		if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s already exists or cannot be checked: %w", p, errors.Join(err, os.ErrExist))
		}
		d, err := os.Stat(filepath.Dir(p))
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return fmt.Errorf("%s is not a directory", filepath.Dir(p))
		}
		dirs[i] = d
	}
	if filepath.Base(a) == filepath.Base(b) && os.SameFile(dirs[0], dirs[1]) {
		return fmt.Errorf("%s and %s are the same file", a, b)
	}
	return nil
}

// createPair creates the key file (0600, via keyfile.Store) and the draft (0644) at paths
// that must not exist. Both are staged first, then linked into place; if the second link
// fails, the first is removed.
func createPair(keyPath string, key []byte, draftPath string, draft []byte) error {
	sfx := make([]byte, 8)
	if _, err := rand.Read(sfx); err != nil {
		return err
	}
	tmpKey := fmt.Sprintf("%s.%x.tmp", keyPath, sfx)
	tmpDraft := fmt.Sprintf("%s.%x.tmp", draftPath, sfx)
	defer os.Remove(tmpKey)
	defer os.Remove(tmpDraft)
	if err := keyfile.Store(tmpKey, key, keyfile.Raw); err != nil {
		return err
	}
	if err := writeNew(tmpDraft, draft, 0o644); err != nil {
		return err
	}
	if err := os.Link(tmpKey, keyPath); err != nil {
		return err
	}
	if err := os.Link(tmpDraft, draftPath); err != nil {
		os.Remove(keyPath)
		return err
	}
	return nil
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
