package pqcrypto

// Contract vectors (§3.8) for transactions, possession proofs, envelopes and receipts.

import (
	"crypto/sha256"
	"encoding/json"
	"testing"
	"time"
)

func init() {
	generators["tx.json"] = genTx
	generators["pop.json"] = genPoP
	generators["envelope.json"] = genEnvelope
	generators["receipt.json"] = genReceipt
	contractFiles = append(contractFiles, "tx.json", "pop.json", "envelope.json", "receipt.json")
}

const (
	wReq1 = "0190b2a4-7777-7777-8777-000000000001"
	wReq2 = "0190b2a4-7777-7777-8777-000000000002"
	wEnv1 = "0190b2a4-8888-7888-8888-000000000001"
	wEnv2 = "0190b2a4-8888-7888-8888-000000000002"
)

// tx builds an unsigned transaction on an account under its context policy.
func (w *world) tx(acct UUID, requester string, a Action) *AccessTransaction {
	a.AccountID = acct
	if a.TargetDescriptorDigest == "" {
		a.TargetDescriptorDigest = w.targetD
	}
	cnf := mustSigningKey(w.t, "cnf/"+string(acct)+"/"+a.ActionType)
	return &AccessTransaction{Header: w.hdr(TypeTx, ScopeAccount, acct, w.pol[acct].Epoch, RoleUser),
		RequestID: wReq1, RequesterPrincipalID: w.users[requester].id, BrokerID: w.brkA.id, PolicyDigest: w.policyDigest(acct),
		CnfPub: cnf.Public(), IssuedAt: NewTime(wT0), ExpiresAt: NewTime(wT0.Add(5 * time.Minute)), Action: a, Approvals: []Approval{}}
}

// finish adds approvals then the requester's signature.
func (w *world) finish(tx *AccessTransaction, requester string, approvers ...string) []byte {
	for _, a := range approvers {
		if err := tx.Approve(w.users[a].id, w.users[a].sig); err != nil {
			w.t.Fatal(err)
		}
	}
	return w.signed(tx, RoleUser, w.users[requester].sig)
}

func txParams(w *world) objParams {
	return objParams{Now: wT0.Add(time.Minute).Format(TimeLayout), BrokerID: w.brkA.id, Seen: []UUID{wReq2},
		Current: &currentParams{wEnv1, "3", hexOf("head")}, CandidateDigest: hexOf("candidate"), CandidateVersion: "5", HighestVersion: "4"}
}

func genTx(t *testing.T) any {
	w := newWorld(t)
	p := txParams(w)
	alice := w.users["alice"]
	checkout := func() *AccessTransaction {
		return w.tx(wAcctE, "alice", Action{ActionType: ActionVaultCheckout, SecretVersion: 3, EncKeyID: alice.encID(), CheckoutTTLSeconds: 900})
	}
	standing := func(recips ...UUID) *AccessTransaction {
		return w.tx(wAcctS, "alice", Action{ActionType: ActionStandingRelease, EnvelopeID: wEnv1, ReceiptHeadHash: hexOf("head"), RecipientPrincipalIDs: recips})
	}
	enroll := func(who string) *AccessTransaction {
		return w.tx(wAcctE, who, Action{ActionType: ActionEnroll, EnvelopeDigest: hexOf("candidate"), SecretVersion: 5})
	}
	carol := w.users["carol"].id

	unknown := checkout()
	unknown.Action = Action{ActionType: "proxy_session", AccountID: wAcctE, TargetDescriptorDigest: w.targetD}
	stale := standing(carol)
	stale.Action.ReceiptHeadHash = hexOf("older head")
	extra := checkout()
	extra.Action.EnvelopeID = wEnv1
	expired := checkout()
	expired.IssuedAt, expired.ExpiresAt = NewTime(wT0.Add(-4*time.Minute)), NewTime(wT0.Add(time.Minute)) // now == expires_at
	long := checkout()
	long.ExpiresAt = NewTime(wT0.Add(11 * time.Minute))
	replay := checkout()
	replay.RequestID = wReq2
	oldBroker := checkout()
	oldBroker.BrokerID = w.old.id
	stalePolicy := checkout()
	stalePolicy.PolicyDigest = hexOf("old policy")
	ttl := checkout()
	ttl.Action.CheckoutTTLSeconds = 3601
	version := checkout()
	version.Action.SecretVersion = 2
	covered := checkout()
	covered.Approvals = []Approval{}
	{ // the approver signs a digest that covered approvals
		canon := w.raw(covered)
		var sigs []Signature
		signOver(t, &sigs, RoleUser, w.users["bob"].sig, sha256.Sum256(append([]byte("kyguard/1/tx\x00"), canon...)))
		bid, _ := w.users["bob"].sig.Public().SigKeyID()
		covered.Approvals = []Approval{{w.users["bob"].id, bid, sigs[0].Sig}}
	}
	roleLie := checkout()
	roleLie.Approvals = nil
	w.finish(roleLie, "alice", "bob")
	roleLie.Signatures[0].SignerRole = RoleCustodian
	notV7 := checkout()
	notV7.RequestID = "0190b2a4-7777-4777-8777-000000000001"
	enrollOld := enroll("alice")
	enrollOld.Action.SecretVersion = 4

	return []objVector{
		vec(t, "vault_checkout with one approval", "tx", TypeTx, w.finish(checkout(), "alice", "bob"), p, ok),
		vec(t, "standing_release to a standing recipient", "tx", TypeTx, w.finish(standing(carol), "alice"), p, ok),
		vec(t, "manual_rotation", "tx", TypeTx, w.finish(w.tx(wAcctE, "alice", Action{ActionType: ActionManualRotation}), "alice", "bob"), p, ok),
		vec(t, "enroll by an enroller", "tx", TypeTx, w.finish(enroll("alice"), "alice", "bob"), p, ok),
		vec(t, "unknown action_type", "tx", "", w.finish(unknown, "alice", "bob"), p, "unknown_action_type"),
		vec(t, "field of another action type", "tx", "", w.finish(extra, "alice", "bob"), p, "invalid_body"),
		vec(t, "standing_release outside the standing list", "tx", "", w.finish(standing(alice.id), "alice"), p, "principal_not_allowed"),
		vec(t, "standing_release with a stale receipt_head_hash", "tx", "", w.finish(stale, "alice"), p, "stale_reference"),
		vec(t, "enroll from a principal outside enroller_principal_ids", "tx", "", w.finish(enroll("dave"), "dave", "bob"), p, "principal_not_allowed"),
		vec(t, "enroll at a version not above the highest seen", "tx", "", w.finish(enrollOld, "alice", "bob"), objParams{Now: p.Now, BrokerID: p.BrokerID, Seen: p.Seen, CandidateDigest: p.CandidateDigest, CandidateVersion: "4", HighestVersion: "4"}, "stale_reference"),
		vec(t, "requester not allowed", "tx", "", w.finish(w.tx(wAcctE, "mallory", Action{ActionType: ActionManualRotation}), "mallory", "bob"), p, "principal_not_allowed"),
		vec(t, "enroll from an allowed user who is not an enroller", "tx", "", w.finish(enroll("bob"), "bob", "bob"), p, "principal_not_allowed"),
		vec(t, "self-approval by a requester who is an approver", "tx", "", w.finish(w.tx(wAcctE, "bob", Action{ActionType: ActionManualRotation}), "bob", "bob"), p, "approvals_not_met"),
		vec(t, "missing approval", "tx", "", w.finish(checkout(), "alice"), p, "approvals_not_met"),
		vec(t, "self-approval", "tx", "", w.finish(checkout(), "alice", "alice"), p, "approvals_not_met"),
		vec(t, "approval from a non-approver", "tx", "", w.finish(checkout(), "alice", "mallory"), p, "approvals_not_met"),
		vec(t, "approval over a digest that covered approvals", "tx", "", w.signed(covered, RoleUser, alice.sig), p, "invalid_signature"),
		vec(t, "requester signature claims signer_role custodian", "tx", "", w.raw(roleLie), p, "signer_role_mismatch"),
		vec(t, "signed by another principal's key", "tx", "", w.signed(func() *AccessTransaction { x := checkout(); x.Approve(w.users["bob"].id, w.users["bob"].sig); return x }(), RoleUser, w.users["dave"].sig), p, "unknown_signing_key"),
		vec(t, "expired", "tx", "", w.finish(expired, "alice", "bob"), p, "outside_validity"),
		vec(t, "lifetime above 10 minutes", "tx", "", w.finish(long, "alice", "bob"), p, "outside_validity"),
		vec(t, "request_id already burned", "tx", "", w.finish(replay, "alice", "bob"), p, "request_replayed"),
		vec(t, "request_id not UUIDv7", "tx", "", w.finish(notV7, "alice", "bob"), p, "invalid_body"),
		vec(t, "addressed to the revoked broker", "tx", "", w.finish(oldBroker, "alice", "bob"), p, "principal_not_allowed"),
		vec(t, "stale policy digest", "tx", "", w.finish(stalePolicy, "alice", "bob"), p, "stale_reference"),
		vec(t, "checkout_ttl_seconds above the policy maximum", "tx", "", w.finish(ttl, "alice", "bob"), p, "principal_not_allowed"),
		vec(t, "secret_version not the current envelope's", "tx", "", w.finish(version, "alice", "bob"), p, "stale_reference"),
	}
}

func genPoP(t *testing.T) any {
	w := newWorld(t)
	tx := w.tx(wAcctE, "alice", Action{ActionType: ActionVaultCheckout, SecretVersion: 3, EncKeyID: w.users["alice"].encID(), CheckoutTTLSeconds: 900})
	cnf := mustSigningKey(t, "cnf/"+wAcctE+"/"+ActionVaultCheckout)
	txRaw := w.finish(tx, "alice", "bob")
	td, _ := ObjDigest(tx)
	other := w.tx(wAcctE, "alice", Action{ActionType: ActionManualRotation})
	od, _ := ObjDigest(other)
	ch := seed("challenge")
	pop := func(d Digest, purpose string) *PossessionProof {
		return &PossessionProof{Header: w.hdr(TypePoP, ScopeAccount, wAcctE, tx.Epoch, RoleCnf), TxDigest: d.Hex(), Purpose: purpose, BrokerChallenge: ch}
	}
	p := objParams{Tx: txRaw, Challenge: ch, Purpose: PurposeDeliver}
	wrongRole := pop(td, PurposeDeliver)
	w.signed(wrongRole, RoleUser, cnf)
	other2 := p
	other2.Challenge = seed("another challenge")
	return []objVector{
		vec(t, "deliver proof", "pop", TypePoP, w.signed(pop(td, PurposeDeliver), RoleCnf, cnf), p, ok),
		vec(t, "proof over another transaction's digest", "pop", "", w.signed(pop(od, PurposeDeliver), RoleCnf, cnf), p, "stale_reference"),
		vec(t, "signature with signer_role user", "pop", "", w.raw(wrongRole), p, "signer_role_mismatch"),
		vec(t, "signed by the requester key, not cnf_pub", "pop", "", w.signed(pop(td, PurposeDeliver), RoleCnf, w.users["alice"].sig), p, "unknown_signing_key"),
		vec(t, "checkin proof where deliver is expected", "pop", "", w.signed(pop(td, PurposeCheckin), RoleCnf, cnf), p, "stale_reference"),
		vec(t, "another challenge", "pop", "", w.signed(pop(td, PurposeDeliver), RoleCnf, cnf), other2, "stale_reference"),
	}
}

// envelope seals a real payload to the given recipients. recov adds the recovery key.
func (w *world) envelope(acct UUID, id UUID, version Counter, recov bool, brokers []*wBroker, users []*wPrincipal) *SecretEnvelope {
	pol := w.pol[acct]
	e := &SecretEnvelope{Header: w.hdr(TypeEnvelope, ScopeAccount, acct, pol.Epoch, RoleBroker), EnvelopeKind: pol.AccountKind,
		EnvelopeID: id, SecretVersion: version, PolicyDigest: w.policyDigest(acct), CreatedAt: NewTime(wT0), Nonce: seed("nonce/" + string(id))[:NonceBytes]}
	if recov {
		e.RecoveryEpoch = 1
	}
	dek := seed("dek/" + string(id))
	ct, err := SealPayload(dek, e.Nonce, e.PayloadAAD(), []byte(`{"password":"Rotated-Secret_0001.!@xyzXYZ0123456"}`))
	if err != nil {
		w.t.Fatal(err)
	}
	e.Ciphertext = ct
	add := func(typ, rid string, pub []byte, kid HexID) {
		r := Recipient{RecipientType: typ, RecipientID: rid, KeyID: kid}
		r.Enc, r.WrappedDEK, err = WrapDEK(pub, e.RecipientAAD(r), dek)
		if err != nil {
			w.t.Fatal(err)
		}
		e.Recipients = append(e.Recipients, r)
	}
	for _, b := range brokers {
		add(RecipientBroker, string(b.id), b.enc.Public().Bytes(), HexID(b.enc.Public().ID()))
	}
	for _, u := range users {
		add(RecipientUser, string(u.id), u.enc.Public().Bytes(), u.encID())
	}
	if recov {
		rid := HexID(w.recovery.Public().ID())
		add(RecipientRecovery, string(rid), w.recovery.Public().Bytes(), rid)
	}
	return e
}

func (w *world) userSigned(e *SecretEnvelope, who string) []byte {
	e.SignerRole = RoleUser
	return w.signed(e, RoleUser, w.users[who].sig)
}

func genEnvelope(t *testing.T) any {
	w := newWorld(t)
	alice, dave := w.users["alice"], w.users["dave"]
	A, old := []*wBroker{w.brkA}, []*wBroker{w.old}
	newP := objParams{New: true}
	rot := w.envelope(wAcctE, wEnv1, 6, true, A, nil)
	rotRaw := w.signed(rot, RoleBroker, w.brkA.sig)
	cand := w.envelope(wAcctE, wEnv2, 5, true, A, nil)
	candRaw := w.userSigned(cand, "alice")
	cd, _ := ObjDigest(cand)
	enrollTx := w.tx(wAcctE, "alice", Action{ActionType: ActionEnroll, EnvelopeDigest: cd.Hex(), SecretVersion: 5})
	enrollRaw := w.finish(enrollTx, "alice", "bob")
	otherTx := w.tx(wAcctE, "alice", Action{ActionType: ActionEnroll, EnvelopeDigest: hexOf("another candidate"), SecretVersion: 5})
	otherRaw := w.finish(otherTx, "alice", "bob")
	badEpoch := w.envelope(wAcctE, wEnv1, 6, true, A, nil)
	badEpoch.RecoveryEpoch = 2
	return []objVector{
		vec(t, "managed rotation envelope with escrow", "envelope", TypeEnvelope, rotRaw, newP, ok),
		vec(t, "historical envelope sealed by and to the revoked member", "envelope", TypeEnvelope, w.signed(w.envelope(wAcctE, wEnv1, 2, true, old, nil), RoleBroker, w.old.sig), objParams{}, ok),
		vec(t, "user-signed enrollment candidate matching its enroll", "envelope", TypeEnvelope, candRaw, objParams{New: true, EnrollTx: enrollRaw}, ok),
		vec(t, "vaulted envelope to the allowed users with escrow", "envelope", TypeEnvelope, w.userSigned(w.envelope(wAcctV, wEnv1, 1, true, nil, []*wPrincipal{alice, dave}), "alice"), newP, ok),
		vec(t, "user recipient in an initial managed envelope", "envelope", "", w.signed(w.envelope(wAcctE, wEnv1, 6, true, A, []*wPrincipal{alice}), RoleBroker, w.brkA.sig), newP, "invalid_recipient_set"),
		vec(t, "recovery recipient with escrow disabled", "envelope", "", w.signed(w.envelope(wAcctS, wEnv1, 6, true, A, nil), RoleBroker, w.brkA.sig), newP, "invalid_recipient_set"),
		vec(t, "no recovery recipient with escrow enabled", "envelope", "", w.signed(w.envelope(wAcctE, wEnv1, 6, false, A, nil), RoleBroker, w.brkA.sig), newP, "invalid_recipient_set"),
		vec(t, "recovery_epoch other than the persisted one", "envelope", "", w.signed(badEpoch, RoleBroker, w.brkA.sig), newP, "invalid_recipient_set"),
		vec(t, "new envelope sealed by the revoked member", "envelope", "", w.signed(w.envelope(wAcctE, wEnv1, 6, true, A, nil), RoleBroker, w.old.sig), newP, "revoked_member"),
		vec(t, "new envelope wrapped to the revoked member", "envelope", "", w.signed(w.envelope(wAcctE, wEnv1, 6, true, old, nil), RoleBroker, w.brkA.sig), newP, "revoked_member"),
		vec(t, "new envelope at a recovery_epoch below the persisted one", "envelope", "", rotRaw, objParams{New: true, Prior: []json.RawMessage{w.signed(w.recoveryManifest(2, false), RoleCustodian, w.cust[0], w.cust[1])}}, "invalid_recipient_set"),
		vec(t, "historical envelope at an older recovery_epoch", "envelope", TypeEnvelope, rotRaw, objParams{Prior: []json.RawMessage{w.signed(w.recoveryManifest(2, false), RoleCustodian, w.cust[0], w.cust[1])}}, ok),
		vec(t, "user-signed managed envelope without an enroll", "envelope", "", candRaw, newP, "no_matching_enroll"),
		vec(t, "user-signed managed envelope with another candidate's enroll", "envelope", "", candRaw, objParams{New: true, EnrollTx: otherRaw}, "no_matching_enroll"),
		vec(t, "vaulted envelope missing an allowed user", "envelope", "", w.userSigned(w.envelope(wAcctV, wEnv1, 1, true, nil, []*wPrincipal{alice}), "alice"), newP, "invalid_recipient_set"),
		vec(t, "vaulted envelope sealed by a principal not allowed", "envelope", "", w.userSigned(w.envelope(wAcctV, wEnv1, 1, true, nil, []*wPrincipal{alice, dave}), "mallory"), newP, "principal_not_allowed"),
	}
}

// receipt builds and signs a receipt on envelope e.
func (w *world) receipt(e *SecretEnvelope, seq Counter, prev HexID, typ, reason string, k *SigningKey, role string, extra []Recipient) (*EnvelopeReceipt, []byte) {
	if extra == nil {
		extra = []Recipient{}
	}
	r := &EnvelopeReceipt{Header: w.hdr(TypeReceipt, ScopeAccount, e.Scope.ID, e.Epoch, role), EnvelopeID: e.EnvelopeID,
		EnvelopeKind: e.EnvelopeKind, SecretVersion: e.SecretVersion, ReceiptSeq: seq, PrevReceiptHash: prev, ReceiptType: typ,
		Reason: reason, OperationID: "0190b2a4-9999-7999-8999-000000000001", ExtraRecipients: extra, IssuedAt: NewTime(wT0)}
	return r, w.signed(r, role, k)
}

func headOf(t *testing.T, r *EnvelopeReceipt) HexID {
	d, err := ObjDigest(r)
	if err != nil {
		t.Fatal(err)
	}
	return d.Hex()
}

// wrapFor wraps a fresh DEK to a user, as extra_recipients carry.
func (w *world) wrapFor(e *SecretEnvelope, u *wPrincipal) Recipient {
	r := Recipient{RecipientType: RecipientUser, RecipientID: string(u.id), KeyID: u.encID()}
	var err error
	r.Enc, r.WrappedDEK, err = WrapDEK(u.enc.Public().Bytes(), e.RecipientAAD(r), seed("dek/"+string(e.EnvelopeID)))
	if err != nil {
		w.t.Fatal(err)
	}
	return r
}

func genReceipt(t *testing.T) any {
	w := newWorld(t)
	A, old := []*wBroker{w.brkA}, []*wBroker{w.old}
	ka, ko := w.brkA.sig, w.old.sig
	alice, dave, carol := w.users["alice"], w.users["dave"], w.users["carol"]

	rot := w.envelope(wAcctE, wEnv1, 6, true, A, nil)
	rotRaw := w.signed(rot, RoleBroker, ka)
	ct, ctRaw := w.receipt(rot, 1, ZeroHex, ReceiptCommitTarget, "", ka, RoleBroker, nil)
	rel, relRaw := w.receipt(rot, 2, headOf(t, ct), ReceiptRelease, "", ka, RoleBroker, nil)
	_, abortDone := w.receipt(rot, 3, headOf(t, rel), ReceiptAbort, ReasonSuperseded, ka, RoleBroker, nil)
	_, rewrapEarly := w.receipt(rot, 2, headOf(t, ct), ReceiptRewrapUser, "", ka, RoleBroker, []Recipient{w.wrapFor(rot, alice)})
	_, fork := w.receipt(rot, 2, hexOf("another head"), ReceiptRelease, "", ka, RoleBroker, nil)
	_, gap := w.receipt(rot, 3, headOf(t, ct), ReceiptRelease, "", ka, RoleBroker, nil)
	_, refused := w.receipt(rot, 1, ZeroHex, ReceiptAbort, ReasonRefused, ka, RoleBroker, nil)
	_, reasonOnCommit := w.receipt(rot, 1, ZeroHex, ReceiptCommitTarget, ReasonRefused, ka, RoleBroker, nil)
	r3, r3Raw := w.receipt(rot, 3, headOf(t, rel), ReceiptRewrapUser, "", ka, RoleBroker, []Recipient{w.wrapFor(rot, alice)})
	_ = r3

	hist := w.envelope(wAcctE, wEnv2, 2, true, old, nil)
	histRaw := w.signed(hist, RoleBroker, ko)
	hct, hctRaw := w.receipt(hist, 1, ZeroHex, ReceiptCommitTarget, "", ko, RoleBroker, nil)
	_, supersede := w.receipt(hist, 2, headOf(t, hct), ReceiptAbort, ReasonSuperseded, ka, RoleBroker, nil)

	vault := w.envelope(wAcctV, wEnv1, 1, true, nil, []*wPrincipal{alice, dave})
	vaultRaw := w.userSigned(vault, "alice")
	vc, vcRaw := w.receipt(vault, 1, ZeroHex, ReceiptVaultCommit, "", alice.sig, RoleUser, nil)
	_, rewrapVault := w.receipt(vault, 2, headOf(t, vc), ReceiptRewrapUser, "", dave.sig, RoleUser, []Recipient{w.wrapFor(vault, dave)})
	_, rewrapOutsider := w.receipt(vault, 2, headOf(t, vc), ReceiptRewrapUser, "", alice.sig, RoleUser, []Recipient{w.wrapFor(vault, carol)})

	std := w.envelope(wAcctS, wEnv1, 6, false, A, nil)
	stdRaw := w.signed(std, RoleBroker, ka)
	sct, sctRaw := w.receipt(std, 1, ZeroHex, ReceiptCommitTarget, "", ka, RoleBroker, nil)
	_, autoRel := w.receipt(std, 2, headOf(t, sct), ReceiptRelease, "", ka, RoleBroker, []Recipient{w.wrapFor(std, carol)})
	_, bareRel := w.receipt(std, 2, headOf(t, sct), ReceiptRelease, "", ka, RoleBroker, nil)

	pr := func(env []byte, new bool, prior ...[]byte) objParams {
		p := objParams{Envelope: env, New: new}
		for _, x := range prior {
			p.Receipts = append(p.Receipts, x)
		}
		return p
	}
	ext := func(local, remote [][]byte) objParams {
		p := pr(rotRaw, false, local...)
		for _, x := range remote {
			p.Remote = append(p.Remote, x)
		}
		return p
	}
	return []objVector{
		vec(t, "commit_target by the active broker", "receipt", TypeReceipt, ctRaw, pr(rotRaw, true), ok),
		vec(t, "release after commit_target", "receipt", TypeReceipt, relRaw, pr(rotRaw, true, ctRaw), ok),
		vec(t, "abort (refused) at seq 1", "receipt", TypeReceipt, refused, pr(rotRaw, true), ok),
		vec(t, "historical receipt by the revoked member", "receipt", TypeReceipt, hctRaw, pr(histRaw, false), ok),
		vec(t, "abort (superseded_by_reenrollment) by the active broker on an envelope sealed to the revoked member", "receipt", TypeReceipt, supersede, pr(histRaw, true, hctRaw), ok),
		vec(t, "rewrap_user after vault_commit", "receipt", TypeReceipt, rewrapVault, pr(vaultRaw, true, vcRaw), ok),
		vec(t, "release with the automatic standing wrap", "receipt", TypeReceipt, autoRel, pr(stdRaw, true, sctRaw), ok),
		vec(t, "new receipt by the revoked member", "receipt", "", hctRaw, pr(histRaw, true), "revoked_member"),
		vec(t, "abort on a completed envelope", "receipt", "", abortDone, pr(rotRaw, true, ctRaw, relRaw), "invalid_receipt"),
		vec(t, "rewrap_user on a rotation envelope before release", "receipt", "", rewrapEarly, pr(rotRaw, true, ctRaw), "invalid_receipt"),
		vec(t, "managed rewrap_user without a standing_release", "receipt", "", r3Raw, pr(rotRaw, true, ctRaw, relRaw), "principal_not_allowed"),
		vec(t, "vaulted rewrap_user to a principal not allowed", "receipt", "", rewrapOutsider, pr(vaultRaw, true, vcRaw), "principal_not_allowed"),
		vec(t, "release without the automatic standing wrap", "receipt", "", bareRel, pr(stdRaw, true, sctRaw), "invalid_recipient_set"),
		vec(t, "receipt fork: previous hash is not the head", "receipt", "", fork, pr(rotRaw, true, ctRaw), "invalid_receipt_chain"),
		vec(t, "receipt gap", "receipt", "", gap, pr(rotRaw, true, ctRaw), "invalid_receipt_chain"),
		vec(t, "reason on a non-abort receipt", "receipt", "", reasonOnCommit, pr(rotRaw, true), "invalid_receipt"),
		vec(t, "remote chain extends the local copy", "extends", "", nil, ext([][]byte{ctRaw}, [][]byte{ctRaw, relRaw}), ok),
		vec(t, "remote chain truncated", "extends", "", nil, ext([][]byte{ctRaw, relRaw}, [][]byte{ctRaw}), "invalid_receipt_chain"),
		vec(t, "remote chain diverges", "extends", "", nil, ext([][]byte{ctRaw}, [][]byte{refused}), "invalid_receipt_chain"),
	}
}
