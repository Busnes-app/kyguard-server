# Build decisions

Readings of `docs/SPEC.md` taken during the Phase 0/1A build where the spec is silent or
contradicts itself. Each names its section. The most secure reading wins.

1. §13 Phase 0, §7.4 (bootstrap removal order). `ensureBootstrapAdmin` and `init-admin` are
   removed in the same PR that adds `kyguard-server break-glass create`. Removing them first
   would leave no way to create an admin, and the smoke, Docker, browser and replica CI jobs
   all sign in as one.
2. §7.2 (SAML removal). `/saml/*` is registered as an explicit 404 rather than deleted
   outright, because the SPA fallback answers every unknown non-API path with 200
   (acceptance test 15 requires 404).
3. §13 Phase 0 (rename). The SQLite file stays `ky_server.db` and the PostgreSQL role and
   database stay `ky_server`: the capsule member path `data/ky_server.db` is part of the base
   restore contract. The inherited `ky_server_base:` domain-separation labels (sealed
   KyRecovery token, replica fingerprint) stay, so the base's pinned fixtures keep proving
   the format.
4. §7.4 (break-glass password). `break-glass create` generates the password (24 characters,
   144 bits) and prints it once with the TOTP URI, rather than reading one from argv (visible in
   process listings) or a terminal. The holder may change it with password + code.
5. §7.4 (403 versus 401). A wrong password answers 401 for every account, so the 403 for an SSO
   account comes only after its password verifies; SSO accounts have no password, so the 403
   cannot enumerate them.
6. §7.4 (break-glass reason). The reason is stored on the session (`sessions.break_glass_reason`),
   set once through `POST /api/auth/break-glass/reason`, and checked by the admin middleware.
7. §7.3 rule 4 (factor binding). The sealed TOTP secret carries its user ID inside the sealed
   bytes, so a `secret_enc` copied onto another user's row does not open.
8. §7.3 rule 5 (counting). Each code attempt is inserted and committed before it is counted, and
   released only on success, so concurrent guesses can only both be refused, never both admitted
   past the limit.
9. §7.2 (SCIM admin refusal). "`checkRole` refuses `admin` unconditionally" is read as: no
   setting can let SCIM grant admin. SCIM may still update, deactivate or demote an account
   that already holds admin from its last sign-in; refusing every write that names admin would
   block deprovisioning an administrator through the directory.
10. §7.2 (SCIM issuer). "The configured SCIM issuer" is `KY_SCIM_ISSUER`, defaulting to
   `KY_KYSIGNON_ISSUER`, because KyIdentity is both the SCIM source and the KySignOn issuer.
11. §7.2 (auth_time). An `auth_time` more than one minute in the future is refused like a stale
   one; the spec states only the 120-second age limit.
12. §7.2 (legacy identities). A database with SSO subjects but no issuer (rows from before
   migration 13) is refused at startup with instructions to set `users.sso_issuer`, rather than
   guessing an issuer. No KyGuard install predates the migration. Those rows may share a subject
   across providers, so the unique `(sso_issuer, sso_subject)` index skips rows with no issuer:
   the migration applies, and the index refuses a duplicate once issuers are set. SCIM refuses
   an `externalId` while no issuer is configured, so it never writes such a row.
12a. §7.2 (fence migration). Migration 13 replaces the sid- and provider-keyed fence tables with
   issuer-keyed ones instead of converting rows: fences live ten minutes and no KyGuard
   install exists.
13. §7.3 rule 3 (enrollment routes). Enrollment is two calls under `/api/auth/stepup/`:
   `enroll` offers a secret (stored sealed on the pending session) and `enroll/confirm` takes the
   first code, stores the factor and exchanges in one transaction. The confirming code's counter
   becomes the factor's `last_counter`, so it cannot be replayed.
14. §7.3 rule 2 (12 hours). The active SSO session lifetime is the constant `SSOSessionTTL`,
   not configurable; `KY_SESSION_TTL` style overrides are not offered.

## Crypto wire format and contracts (§3)

Numbered separately: these came from the parallel crypto stack.

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
61. §4.1 (sync frame bound). `cptrust.Submit` refuses a manifest over 512 KiB
    (`MaxManifest`), so any stored manifest fits a 4 MiB channel frame base64url-encoded. A
    `sync` page carries at most 64 manifests whose encoded size stays within `SyncBudget`
    (2 MiB), and always at least one, so every page advances.
62. §4.1 (sync read and reply bound). A `sync_account` page is the chains above the
    request's `from`, in version order: the open ones at or below the broker's version
    (current, or without `abort`, `release` or `vault_commit`), then every newer one. It
    reads at most `SyncChains + 1` (65) chains and the whole reply, descriptor included,
    stays within `SyncBudget`; a page always carries one chain. The store caps one chain
    (envelope plus receipts) at 256 KiB and a descriptor at 64 KiB (`store.ErrTooLarge`), so
    a one-chain page always fits a frame and every continuation advances. A `sync` page reads
    at most `SyncPage` manifests. A `receipts` request reads only the chains its receipts
    name.
70. §4.1 (pushes). A Control Plane push that finds the broker's 16-slot queue full is
    dropped and logged, never waited for, so results for pending calls keep flowing. A
    dropped push is a lost relay: nothing was persisted, and the CLI retries or the
    reservation expires.
71. §3.5 (duplicate completion). A completion whose receipts are all already stored is a
    retry and changes no derived state (current envelope, run state, lock). The current
    envelope only ever moves to a higher `secret_version`.
77. §3.5, §3.6 (chain room for completion). The spec bounds neither a chain's size nor
    `standing_recipient_principal_ids`. A policy may name at most 32 standing recipients
    (`pqcrypto.MaxStandingRecipients`; refused as `invalid_body`), and the Control Plane
    stores an envelope only if it leaves 96 KiB of the 256 KiB chain (`store.MaxEnvelope`).
    That room holds `commit_target` plus a `release` with all 32 wraps, so an admitted
    rotation can always finish and give back its lock.
