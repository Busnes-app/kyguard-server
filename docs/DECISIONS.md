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
   pin requests hold no shared lock, so startup and the next request of the same kind settle
   only intents older than 20 minutes (longer than any detached backup request). A pending
   intent settles to its noted outcome, else to `outcome_unknown` with a critical
   `operation.outcome_unknown` record. A noted outcome carries an HMAC under a key derived from
   the audit chain key. The HMAC binds the operation ID, kind, subject, state and exact record,
   and a note that fails it ends `outcome_unknown` with `operation.outcome_rejected`; its record
   is never appended. Settling is one conditional `UPDATE`. Reconciliation moves only `pending`
   intents, so concurrent reconcilers append once, and the owning process may still correct an
   `outcome_unknown`. A completed deposit supersedes every `outcome_unknown`
   deposit, and a fresh capsule is sealed for each run, so lost bytes are never replayed.
19b. §9.3 (states). Besides the spec's `pending`, `complete`, `outcome_unknown` and `superseded`,
   an intent can end `failed`: the effect was refused, or it happened and the local completion
   failed, and either way the outcome is known. The table is a superset of the broker stack's
   migration-100 table, so the stack join drops that one.
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
