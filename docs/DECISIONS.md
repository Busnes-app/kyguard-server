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
15. §7.5 (broker listener). The classification test covers the main mux only; the broker
   listener (`/broker/v1/*`, §4.1) is Phase 1A work and the test must be extended to it there.
16. §7.3 rule 6 (re-step-up). An active session refreshes its step-up with a code at
   `/api/auth/stepup/totp`, the same route a pending session uses. Break-glass sessions start
   stepped up at sign-in, so backup actions in their last 25 minutes need a fresh code too.
16a. §7.3 rule 6, §7.5 (broker routes on the main mux). `POST /api/broker-pools` and
   `POST /api/broker-pools/{id}/pairing-tokens` are session routes with the 5-minute window
   (broker and pairing actions). `POST /api/manifests` is a session route with no window: rule 6
   does not list it, and the manifest's Custodian signatures are what authorize it.
17. §9.3 (stored values). Audit fields pass through `logging.AuditFields`, which bounds each
   value to 256 bytes; the stored columns hold those rendered values, so nothing outside the hash
   is stored.
18. §9.3 (key plumbing). The chain key travels as `config.DatabaseConfig.AuditKey`; stores opened
   without it (backup drill scratch copies, migration sources) can read but refuse audit writes.
18a. §9.3 (upgrade and verification). Records written before migration 15 have no chain fields.
   Migration 15 chains them inside its own transaction, oldest first, in their canonical form,
   so the first append finds one chain. An interrupted upgrade leaves both undone and the next
   start retries them, and without the chain key a database holding such records refuses to
   migrate. No later open signs anything, so a row a writer without the key
   inserts unchained stays unchained and verification reports it. Forging the trigger means
   deleting the migration's record, and then the migration's `ALTER TABLE` fails and the start
   is refused. Verification rejects any stored field that differs from its
   canonical rendering, because the HMAC covers only that rendering. On PostgreSQL it reads the
   head and the records in one REPEATABLE READ snapshot.
19. §9.3 (external effects). A KyRecovery pairing claim, a recovery-key pin and a deposit each
   commit an `operation_intents` row before the effect starts. The run's or request's audit
   record is the completion append, in the same transaction that ends the intent, and it is
   noted on the intent first. So when that append fails, the action answers 500
   (`ErrNotRecorded`) and reconciliation later appends the noted record. Nothing is only logged.
   A deposit intent is taken only when a deposit can go out (paired) and after the payload is
   collected, so refused and local-only runs leave none.
19a. §9.3 (reconciliation). Deposits run under the `backup-run` lock, so `backup.Run`, and
   startup when it wins that lock, settle every pending deposit before depositing. Pairing and
   pin requests hold no shared lock, so startup, the next request of the same kind and every
   tick of the elected scheduled worker settle only intents older than 20 minutes (longer than
   any detached backup request). The worker tick runs only while the backup scheduler does; a
   deployment key that cannot seal stops it, leaving startup and the next request. A pending
   intent settles to its noted outcome, else to `outcome_unknown` with a critical
   `operation.outcome_unknown` record. A noted outcome carries an HMAC under a key derived from
   the audit chain key. The HMAC binds the operation ID, kind, subject, state and exact record,
   and a note that fails it ends `outcome_unknown` with `operation.outcome_rejected`; its record
   is never appended. Settling is one conditional `UPDATE`. Reconciliation moves only `pending`
   intents whose note is still the one it read, so concurrent reconcilers append once, a note
   written after the read is replayed on the next pass rather than lost, and the owning process may still correct an
   `outcome_unknown`. A completed deposit supersedes every `outcome_unknown`
   deposit, and a fresh capsule is sealed for each run, so lost bytes are never replayed.
19b. §9.3 (states). Besides the spec's `pending`, `complete`, `outcome_unknown` and `superseded`,
   an intent can end `failed`: the effect was refused, or it happened and the local completion
   failed, and either way the outcome is known.
19d. §9.3 (one table, two stacks). Migration 100 (broker stack, merged) creates
   `operation_intents`. Migration 200 rebuilds it, rows kept, as the superset this stack needs
   (`outcome`, `failed`, an index on `(kind, state)`); SQLite cannot change a CHECK in place.
   The auth stack's migrations after the broker's take versions from 200, and a test fails if
   the registry is not ascending. A KyRecovery pairing claim is kind `recovery_pairing`:
   `pairing` is a broker pairing, settled only by the Guard store's sweep, so neither
   reconciler ends the other's intents. No KyGuard install exists, so no database holds a
   history these renumbered migrations would contradict.
19c. §9.3 (settings publication). `UpdateSettings` appends the record `store.WithAudit` attaches,
   in its transaction, so the exempt-network list and its record commit together. Backup export,
   unpair and schedule now fail on a failed audit append. Export sends no capsule bytes without
   the record. Unpair and schedule answer 500, saying that the change landed and its record did
   not.
19d. §9.4 (broker CA). The capsule carries `data/broker-ca.key` and `data/broker-ca.crt` when the
   data directory holds them. One without the other refuses to seal, because a restore could not
   run brokers with half a CA. The start-time checks of the restored CA (its key matches its
   certificate, and every paired broker's pinned hash matches) need the broker tables from the
   broker stack, so they come with the stack join.
19e. §9.4 (restore). The restored copy loses its sessions, every CLI login code, and the broker
   pairing tokens not yet consumed. Consumed tokens stay as the record of which broker each one
   paired. The CLI-code and pairing-token tables are cleared when present, so a capsule from
   before either feature restores too.
19f. §9.4 (seal gate). The gate compares the pinned key and topology against the verified
   `RecoveryKeyManifest`. That verifier is on the trust stack (#4), which is not joined to this
   stack, so the gate is not built here. Built fail-closed in this stack, it would refuse every
   pin and backup; built fail-open, it would be a hole if merged alone. It is a join task.
19g. §7.6 (CLI login). The login takes `cli_port` (1024–65535) and an S256 `cli_challenge`,
   held in a state-bound cookie for the callback. The callback issues no browser session; the
   code goes only to `http://127.0.0.1:<port>/cb`. A code is spent by its first redemption
   attempt, even with a wrong verifier, and an expired code is deleted when it is tried. The
   redemption's pending session goes through `CreateSession`, which inserts, commits and then
   re-checks both fences against the original `iat`. After step-up, a bearer caller gets the new
   active token in the body; a cookie caller never does, so page script cannot read it.
   A factor reset deletes the user's outstanding CLI codes first, in its transaction.
   Redemption deletes the code and inserts the session in one transaction, so the code row
   orders the two: a code redeemed first loses its session to the reset, and a code the reset
   reached first redeems nothing.
19h. §7.3 rule 6 (web re-step-up). `secureFetch` turns a 403 `stepup_stale` into a code prompt
   (the shell's `ReStepUp` dialog posts it to `/api/auth/stepup/totp`). On success it sends the
   original request once more; on cancel the caller gets the 403 as before. Every other 403 goes
   straight to the caller.

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
63. §4.2, §4.3 rule 7 (undelivered results). A run whose journaled receipts the Control
    Plane has not acknowledged is never replaced: the next rotation attempt first re-sends
    them and, if that fails, is refused as blocked, so an abort's operation ID and the
    reservation it releases are never lost.
64. §8.1, §4.3 rule 6 (health delivery). A health report that fails is journaled as
    unreported and sent again by every `Recover` (startup and reconnect) until one is
    acknowledged, so a quarantine is never left unknown to the Control Plane.
65. §4.4 (AD effective minimum age). `PasswordAge` reports the minimum age of the policy
    that actually governs the account: when the account's `msDS-ResultantPSO` names a
    fine-grained password settings object, its `msDS-MinimumPasswordAge`; otherwise the
    domain's `minPwdAge`. If the account can see its resultant PSO but cannot read the
    PSO's minimum age (AD's default ACL hides PSOs from ordinary accounts), the minimum age
    is unknown and `PasswordAge` fails: the domain value could be shorter than the enforced
    one and schedule retries into refusals that spend the three-refusal limit, so the
    broker keeps its previously known deadline instead. Deployments that use PSOs grant the
    account read access to its PSO. A directory that hides `msDS-ResultantPSO` itself is
    indistinguishable from no PSO, and the domain value is reported.
66. §4.4 (connector cancellation). Every target operation observes its context: the
    `ad_ldaps` connector closes the connection when the context ends during a bind, search
    or modify (go-ldap requests otherwise wait for the fixed timeout), and `Change` sends
    no modify once the context has ended, checked again after the intent commits.
70. §4.1 (pushes). A Control Plane push that finds the broker's 16-slot queue full is
    dropped and logged, never waited for, so results for pending calls keep flowing. A
    dropped push is a lost relay: nothing was persisted, and the CLI retries or the
    reservation expires.
71. §3.5 (duplicate completion). A completion whose receipts are all already stored is a
    retry and changes no derived state (current envelope, run state, lock). The current
    envelope only ever moves to a higher `secret_version`.
72. §3.4, §4.2 (reservation recovery). An attempt is journaled `reserving`, with the highest
    version seen so far, before the broker asks for a version. Recovery (or the next
    rotation) reserves again under the same operation ID; the Control Plane returns that
    operation's own reservation, which is accepted if it is above the version seen before
    and above every envelope the broker holds, even when sync has since copied it into the
    high-water mark. The run is then sealed, stored and aborted (`restart_before_send`) so
    the lock is released. A refusal means nothing was reserved and the run ends with
    nothing to send. `reserving` is a journal state, not a §4.2 state, and blocks the account.
73. §8.1 (health delivery). Every health change sets `Unreported` in the same journal save,
    and only an acknowledged report clears it, so a crash between the save and the report
    still leaves the health to be sent by `Recover`.
74. §4.4 (minimum age source). Besides enrollment, the broker reads the account's last
    change and the target's minimum password age at every pre-rotation login, through the
    connector's `AgeReporter`, so the schedule stop and refusal retries use the target's
    real values; a connector that cannot read them leaves the journaled values unchanged.
77. §3.5, §3.6 (chain room for completion). The spec bounds neither a chain's size nor
    `standing_recipient_principal_ids`. A policy may name at most 32 standing recipients
    (`pqcrypto.MaxStandingRecipients`; refused as `invalid_body`), and the Control Plane
    stores an envelope only if it leaves 96 KiB of the 256 KiB chain (`store.MaxEnvelope`).
    That room holds `commit_target` plus a `release` with all 32 wraps, so an admitted
    rotation can always finish and give back its lock.

## Post-quantum key exchange (PQC plan W0, owner-approved 2026-11-25)

80. §4.4, §11 (SSH key exchange). The `ssh_passwd` connector sets `KeyExchanges` explicitly to
    `mlkem768x25519-sha256`, `curve25519-sha256`, `curve25519-sha256@libssh.org` and
    `ecdh-sha2-nistp256/384/521`, in that order. The x/crypto default also offers
    `diffie-hellman-group14-sha1` and `diffie-hellman-group14-sha256`; a target offering only
    those is refused before any credential is sent. Under `fips140=on` x/crypto registers no
    curve25519 exchange, so the list narrows to the hybrid and NIST ECDH.
81. §4.1, §11 (broker TLS groups). Both ends of the broker channel are KyGuard on Go 1.27, so
    the listener and the broker client offer and accept only `X25519MLKEM768` (PQC plan Q9).
    A peer offering only classical X25519 fails the handshake. The pinned-CA check is unchanged.
