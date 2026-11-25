# Build decisions

Readings of `docs/SPEC.md` taken during the Phase 0/1A build where the spec is silent or
contradicts itself. Each names its section. The most secure reading wins.

1. §13 Phase 0, §7.4 (bootstrap removal order). The scaffold PR leaves `ensureBootstrapAdmin`
   and `init-admin` in place; the break-glass PR removes them together with adding
   `kyguard-server break-glass create`. Removing them first would leave no way to create an
   admin, and the smoke, Docker, browser and replica CI jobs all sign in as one.
2. §7.2 (SAML removal). `/saml/*` is registered as an explicit 404 rather than deleted
   outright, because the SPA fallback answers every unknown non-API path with 200
   (acceptance test 15 requires 404).
3. §13 Phase 0 (rename). The SQLite file stays `ky_server.db` and the PostgreSQL role and
   database stay `ky_server`: the capsule member path `data/ky_server.db` is part of the base
   restore contract. The inherited `ky_server_base:` domain-separation labels (sealed
   KyRecovery token, replica fingerprint) stay, so the base's pinned fixtures keep proving
   the format.
4. §3.1 (JSON numbers). Signed objects allow only integers in [-(2^53-1), 2^53-1], with no
   fraction, exponent or `-0`; in that range RFC 8785 number serialization is plain decimal
   in every runtime. Counters stay decimal strings (rule 2).
5. §3.1 rule 1 (strict typed decoding). A received object must re-encode from its typed form
   to the same JCS bytes as its input. This rejects unknown fields, case-variant keys (Go's
   `encoding/json` matches keys case-insensitively), explicit empty values for omitted
   fields and `null` in place of a value.
6. §3.1 rule 3 (timestamps). The one accepted form is `YYYY-MM-DDTHH:MM:SSZ`: UTC, whole
   seconds, no fraction, so the JCS bytes are identical across runtimes.
7. §3.1 rule 3 (base64url). Padding, the standard alphabet, non-zero trailing bits and
   embedded CR or LF are rejected. Go's decoder skips CR/LF even in strict mode, so they are
   refused first.
8. §3.1 rule 4 (`D(obj)`). Only the top-level `signatures` and `approvals` members are
   removed; nested objects keep theirs, so `bootstrap_fingerprint` covers the signatures of
   the bundled manifests. `<type>` must match `^[a-z][a-z0-9_]*$`.
9. §3.1 (AAD field checks). The AAD builders refuse an `envelope_kind` other than
   `managed`/`vaulted`, a `recipient_type` other than `broker`/`user`/`recovery`, and a
   `recipient_id` without that type's form (UUID for broker and user, 64-hex for recovery).
   `WrapDEK` and `UnwrapDEK` refuse an AAD whose `key_id` is not the `enc_key_id` of the key
   in use.
10. §3.4 (`opid`). The first 16 digest bytes are formatted `8-4-4-4-12` lowercase hex with no
    UUID version or variant bits forced; the spec says only "formatted as a UUID", and
    forcing bits would discard digest entropy.
11. §3.2 (scope). `scope.id` must equal the body's own ID: `deployment_id` for the custodian
    set and recovery manifest, `pool_id`, `account_id` or `principal_id` otherwise.
12. §3.2, §3.7 (signatures). Every signature on an object must resolve to a key of its stated
    role and verify; one bad signature rejects the object even when M others verify.
13. §3.7 rule 1 (successor manifests). A same-epoch, same-digest manifest is idempotent even
    if re-signed (D excludes signatures); the first copy is kept. Between epochs:
    the custodian set advances by exactly 1, so the chain from the bundle is complete; the
    recovery key and topology are frozen (§9.4, D.7); pool members are never dropped or
    changed, a revoked member never becomes active again, decommission records are kept and
    name only revoked members; a key enrollment keeps its issuer and subject, keeps every
    listed key and never re-activates a revoked one; a policy keeps its `account_kind`. A user
    key may be enrolled to only one principal.
14. §3.3 (policy shape). The six managed-only fields are absent on a vaulted policy and
    present on a managed one; a vaulted policy has `rotation_schedule: null`.
15. §3.4, §3.5 (single signer). Transactions, envelopes, receipts and possession proofs carry
    exactly one signature. Any invalid, duplicate or unlisted approval rejects the whole
    transaction, rather than being skipped while others meet the count.
16. §3.4, §3.5 (IDs). `request_id` and `envelope_id` must be UUIDv7.
17. §3.4 (scope of the library). The journal-state checks (open rotations and leases,
    quarantine, the enrollment reset rule) are the broker's (Phase 1A). `VerifyTx` does the
    checks that need only signed state plus the context the broker passes in.
18. §3.5 (history versus new work). A historical envelope may name any recovery epoch from 1
    up to the persisted one; a new envelope must name the persisted one. A historical
    receipt's epoch is at least its envelope's; a new receipt's epoch is the current policy
    epoch. A sealing context resolves only to a policy accepted in order. New work is
    authorized by the current policy: a new envelope must be sealed under it, and a new
    receipt's broker must belong to its pool and its users to its lists, so a broker of a
    pool the account has left is refused. History is judged by the policy at the receipt's
    epoch if it was accepted, otherwise by the sealing policy, so removing a user never
    breaks replay of a valid chain.
19. §3.5 (abort reasons). `refused` and `restart_before_send` appear only at seq 1 of a
    broker-sealed rotation envelope, `enrollment_failed` only at seq 1 of a user-signed
    enrollment candidate, and `superseded_by_reenrollment` at the next seq of any unterminated
    envelope. A vaulted `rewrap_user` signer must already be a user recipient (initial or
    added by an earlier rewrap).
20. §3.1, §3.2 rule 6 (key files). Argon2id comes from `golang.org/x/crypto/argon2`, the
    implementation `ky-primitives/password` uses, at `password.DefaultParams()`. It derives
    an AES-256-GCM key that seals the seeds; the clear header (kind, ID, key IDs, KDF
    parameters) is the AAD, so it cannot be edited without the passphrase. New passphrases
    need at least 12 characters.
21. §3.2 rule 2 (`kyguard-cli init`). Every custodian signs both epoch-1 manifests, not just
    M, and init verifies the bundle against its own fingerprint before writing it.
22. §3.2 rules 3 and 5 (`trust`). Replacing a pin with a different fingerprint needs
    `--replace`; a failed `trust` leaves no state behind.
23. §3.2 rule 3 (manifest intake). `kyguard-cli import` is how the CLI accepts manifests
    offline and records their high-water marks (the spec names no command for it). It
    alerts on equivocation.
24. §3.2 rule 4 (`sign`). The CLI refuses to sign a managed policy without a target
    descriptor whose recomputed digest, account and deployment match the policy, and
    refuses a signing key outside the current custodian set.
25. §3.3, §13 (`enroll`). Phase 0 enrolls a principal's first key only; adding or rotating
    keys, which needs self-signatures by the existing active keys, comes later.
26. §7.6 (Control Plane client). The CLI reaches the Control Plane only through
    `cli.Client`. The session-backed HTTP implementation arrives with `kyguard-cli login`,
    together with the Control Plane's draft and manifest endpoints; Phase 0 commands take
    files.
27. §3.1, §9.4 (decrypt boundary). `TestNothingInTheServerDecrypts` exempts exactly one
    function outside the restore command: `internal/cli/keyfile.go` `openKeyFile`. It
    rebuilds a user's own X-Wing key from that user's passphrase-sealed key file with
    `recoverykey.FromSeed` (§3.1 names `recoverykey` for these keys); it is part of
    `kyguard-cli`, not the server, and never handles the suite recovery key.
28. §3.2 rules 3 and 5 (`trust`, same fingerprint). Re-pinning the fingerprint already
    pinned changes nothing, with or without `--replace`: every accepted manifest and
    signing commitment stays. A different fingerprint with `--replace` keeps this CLI's
    signing commitments too, since they only ever refuse more.
29. §3.2 rules 3 and 4, §3.7 rule 1 (`sign`, below quorum). The spec's high-water mark
    covers accepted manifests only. `kyguard-cli` also persists, before any signature
    leaves, the highest `(epoch, digest)` it has signed per `(type, scope.id)` and refuses
    a lower epoch or a same-epoch fork against it, even when the earlier draft never
    reached quorum. The commitment is per CLI state directory, not per custodian key, so
    custodians sharing one state are bound together (the stricter reading). An abandoned
    draft is replaced by a draft at the next epoch.
30. §3.2 rule 4 (`sign`, existing signatures). Before releasing a signature the CLI runs
    every acceptance check on the signed draft (`pqcrypto.Trust.Check`); only a short
    custodian quorum may remain. An invalid co-signature, a missing self-signature or a
    broken successor rule refuses the draft.
31. §3.2 rule 3 (state concurrency). `trust`, `import`, `enroll` and `sign` hold an
    exclusive OS file lock on `$KYGUARD_HOME/trust.lock` for the whole command, so
    concurrent `kyguard-cli` processes run one at a time and none saves a stale snapshot.
    A second command waits while the first one prompts.
32. §3.2 rule 4 (`enroll` delivery). Before generating keys, `enroll` checks that the key
    and draft paths are distinct, absent and in existing directories. It stages both files
    and links them into place without replacing anything; if the draft cannot be placed,
    the new key file is removed. A failed Control Plane submission keeps both files.
33. §9.2 (trust tables). The Control Plane keeps every accepted manifest in one
    `trust_manifests` table ordered by `seq` instead of five per-type tables: `Trust.Accept`
    checks each manifest against the custodian set current at its turn, so replay needs one
    global acceptance order. `bootstrap_bundles` holds the single imported bundle.
34. §4.1, §9.4 (broker CA). The CA, listener and broker TLS keys are Ed25519. The CA lasts 20
    years and broker certificates 10; renewal is later work, and revocation is the pool
    manifest, not the certificate. `kyguard-server init` creates only the CA; the listener
    leaf (1 year) is issued at every start, which §9.4 requires after restore anyway.
35. §4.1 (broker identity in the certificate). `broker_id` is bound as the URI SAN
    `urn:uuid:<broker_id>` and the subject CN; a random 128-bit value formatted as a UUID
    with no version bits forced (as decision 10).
36. §4.1 (channel admission). Besides `active` in the pool manifest, the presented
    certificate's SHA-256 must equal the manifest's `mtls_cert_sha256`, so a second
    internal-CA certificate for a listed `broker_id` is refused.
37. §9.3 (pairing intent). The pairing intent ends `complete` only when the response was
    written and flushed; a write error marks it `outcome_unknown` at once. Startup, and then
    a loop every minute, marks intents still `pending` after 2 minutes `outcome_unknown`,
    leaving younger ones to a replica that may still be answering.
38. §9.2 (migration numbering). Broker-stack migrations take versions from 100 so the two
    parallel stacks never reuse a version; they run after every Phase 0 migration.
39. §9.2, §8.1 (minimal accounts). The broker stack's migration 101 creates `assets` and
    `accounts` with only the columns it needs (`pool_id`, `current_envelope_id`,
    `min_password_age_seconds`, `owner_user_id`, `status`, the version high-water mark and
    the broker-reported `health`); the inventory work adds the rest.
40. §4.3 rule 7 (completion). The Control Plane derives the outcome of a receipts request
    from the verified receipts: `release` makes its envelope current, marks the run
    `release_authorized` and deletes the operation's lock; `abort` marks it `aborted` and
    deletes the lock; `commit_target` marks it `target_verified`. The broker's own claims
    about state are never trusted.
41. §4.1 (channel scope). Every channel request is re-authorized: the broker must be its
    pool's active member at that moment, and the account's current policy must be managed
    and name that pool.
42. §4.2, §4.6 (abort reasons before the write). `refused` is used only for a deterministic
    target refusal; every other attempt that ends with no write sent (no acknowledgement,
    a connection or login failure before the commit point, an authentication failure that
    also quarantines) uses `restart_before_send`, the reason whose meaning is "no write was
    sent".
43. §4.3 rule 5 (one probe). The verification of an acknowledged write and the probe of an
    ambiguous one are the same single `P_new` login, journaled before it is sent; a failed
    verification after an acknowledged write quarantines rather than trying again.
44. §4.2 (prepared). `prepared` is journaled as soon as the version is reserved and `P_new`
    is sealed, before the envelope is stored at the Control Plane and before the `P_old`
    login, so a crash anywhere before the intent ends in a clean abort that also releases
    the lock. The baseline travels in the intent.
45. §3.7 (broker copy). The broker keeps every envelope and receipt chain it has seen, not
    only the current one; sync adopts a Control Plane chain only if it extends the
    broker's copy byte for byte.
46a. §3.3 (target change). Phase 1A rotates and checks out only while the current envelope's
    sealing policy pins the same descriptor as the current policy; otherwise health is
    `needs_enrollment` and nothing is sent. Recovery probes the descriptor of the intent's
    own envelope. Deferring a descriptor-changing policy while an intent or lease is open
    (the full §3.3 rule) is not built yet.
46. §3.4 (skipped occurrences). Skipping is implicit: when the latest outstanding occurrence
    releases, its due time becomes the floor, so every earlier one is no longer
    outstanding. The broker journals the occurrence each run belongs to, not a skip list.
47. §4.4 (three refusals). The refusal counter is per account across occurrences and resets
    on `release` and on a new policy epoch; `next_attempt_at` and the minimum-age deadline
    carry across epochs.
48. §4.4 (LDAP client). The `ad_ldaps` connector uses `github.com/go-ldap/ldap/v3` over a
    TLS connection it dials itself. The library also contains NTLM and GSSAPI binds; the
    connector never calls them (simple bind only), so §4.4's "no NTLM, no Kerberos" holds.
    TLS 1.2 is the floor because supported Windows Server releases do not all offer 1.3.
49. §4.4 (AD outcomes). LDAP result 49 (invalid credentials, including `52e`) is the
    deterministic authentication failure; 19 (constraint violation: policy, history,
    minimum age) and 53 (unwilling to perform) on the `unicodePwd` modify are deterministic
    refusals. Any other error after the commit point is ambiguous.
50. §4.4 (SSH prompts). The connector runs `LC_ALL=C passwd` so the linux-pam prompts are the
    English set; it answers only "Current password" / "(current) UNIX password", then
    "New password" / "Enter new UNIX password", then "Retype new password". A repeated new
    password prompt after the commit point is a refusal (linux-pam rejected it and wrote
    nothing); success needs "password updated successfully" and exit status 0. An
    unrecognized prompt is detected by the absence of a known one within the timeout.
51. §4.4 (SSH baseline). SSH verification is the fresh login alone; the baseline is the
    `chage -l` last-change date when the account may read it and empty otherwise.
52. §4.5 (quarantine on the Control Plane). The Control Plane allows a reservation over a held
    lock only when the broker last reported the account `quarantined` or `auth_failed`; the
    broker checks again and refuses an enrollment while a rotation is open on a healthy
    account.
53. §4.5 (which operation signs the aborts). The `abort` (`superseded_by_reenrollment`)
    receipts carry the enrollment's `operation_id`; the stuck run they end is found by the
    envelope's `secret_version` and marked `aborted`.
54. §4.5 (CLI wiring). `cli.SealEnrollment` is the CLI's half (seal, sign the candidate and
    the `enroll` transaction from its own verified state); the `kyguard-cli vault enroll`
    command lands with the session-backed `cli.Client` (§7.6).
