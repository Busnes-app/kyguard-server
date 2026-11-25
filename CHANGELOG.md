# Release notes

[Overview](README.md) · [Restore and image verification](docs/RESTORE.md) · [Design spec](docs/SPEC.md)

## Reading a release

KyGuard distributes rolling containers identified by their full source commit, not SemVer
tags. For a published `:<commit>` image, read **Current source** in this file at that exact
commit: `https://github.com/Busnes-app/kyguard-server/blob/<commit>/CHANGELOG.md#current-source`.
History before the KyGuard import is `ky-server-base` at `fed0fb3` and its own `CHANGELOG.md`.

## Current source

### Changes

- Renamed the product to KyGuard: the binary, image and container are `kyguard-server`, the
  default `KY_APP_NAME` (KyRecovery service label) is `KyGuard`, and CI runs on `main`.
- Removed the SAML 2.0 service-provider helper, its `/saml/metadata` route (now 404) and the
  `KY_SAML_ENTITY_ID` and `KY_SAML_METADATA_URL` settings (spec §7.2).
- Removed the base's product-scaffolding script (`scripts/ky-init.sh`); KyGuard is a product.
- KyGuard `internal/pqcrypto` wire format (spec §3.1): strict RFC 8785 JCS, decimal-string
  counters capped at 2^63-1, unpadded base64url, the domain digest `D(obj)`, ML-DSA-65 +
  Ed25519 hybrid signatures, `sig_key_id`/`enc_key_id`, the payload and DEK-wrap AADs, the
  X-Wing HPKE DEK wrap, the AES-256-GCM payload and `opid`, with committed golden vectors.
- KyGuard trust root and manifests (spec §3.2, §3.3, §3.7): the bootstrap bundle and its
  fingerprint, the five Custodian-signed manifests with M-of-N and the per-`(type, scope.id)`
  epoch and fork rules, and the target descriptor, as a verifier library with golden vectors.
- KyGuard transactions, envelopes and receipts (spec §3.4, §3.5, §3.7): access transactions
  with all four actions, approvals and possession proofs; secret envelopes with the signer,
  recipient and escrow rules; receipt chains with compare-and-swap, the current-envelope rule
  and the chain-extension check, with golden vectors.
- `kyguard-cli` (spec §3.2): `init` runs the offline ceremony (custodian key files, the
  epoch-1 manifests and the bootstrap bundle, with a 1-of-1 warning), `trust` pins the
  fingerprint, `import` records verified manifests and refuses rollback and forks,
  `enroll` creates a user's keys and a self-signed key enrollment draft, and `sign` shows
  a draft decoded (principals resolved, target descriptor recomputed, Control Plane labels
  marked unverified) before applying a Custodian signature. Commands that read or write
  the trust state run one at a time; `sign` checks the whole draft before releasing a
  signature and remembers what it signed; `enroll` creates the key file and its draft
  together or not at all.
- Broker listener and pairing (spec §4.1): `kyguard-server init` creates the internal broker
  CA and `import-bundle` installs the bootstrap bundle after checking its fingerprint.
  Admins create broker pools and one-time, 10-minute pairing tokens. A separate TLS 1.3
  listener on `KY_BROKER_LISTEN` pairs brokers and admits to its control channel only a
  broker that a Custodian-signed pool manifest lists as active with that certificate.
  `POST /api/manifests` admits Custodian-signed manifests on the Control Plane. Startup
  refuses a broker CA that paired brokers did not pin.
- `kyguard-broker` (spec §4.1): `pair` creates the broker's keys on the host (one 0600 key
  file), pairs it and prints the identity the Custodians check; `run` sets `RLIMIT_CORE=0`
  and holds the control channel. A hardened systemd unit is in `deploy/broker`.
- Control Plane vault storage and broker channel requests (spec §3.5, §4.3): one rotation
  lock per account and `secret_version` allocation that never goes below what the broker
  reports; envelopes, receipts (compare-and-swap) and rotation intents stored only after
  verification; completion moves the current envelope and releases the lock atomically,
  and re-sending a completed result changes nothing.
- Broker rotation state machine (spec §4.2, §4.3, §4.6): the journal keeps verified
  manifests, descriptors and a per-account copy of every chain; a rotation journals each
  durable state, sends the target write only after the Control Plane acknowledged the
  intent, and settles an unknown outcome only by one journaled `P_new` probe or quarantine.
  A restart never writes twice. A denied current credential stops after one attempt and
  quarantines. Sync refuses older or forked manifests and chains older than the broker's.
- Broker-local scheduler (spec §3.4, §4.4): the broker runs each account's signed schedule by
  its own clock, every minute and on nudges, and runs only the latest outstanding
  occurrence after the schedule floor; refused attempts wait for `next_attempt_at` and
  stop after three until a new policy epoch; a minimum password age above the interval
  runs nothing.
- Active Directory connector (spec §4.4): self-change over LDAPS against the descriptor's
  pinned CA and host name, baseline `pwdLastSet`/`msDS-KeyVersionNumber`, verification by
  a fresh bind, and minimum password age from the domain; tested in CI against Samba AD at
  `min-pwd-age=0` and at the default of one day.
- Linux SSH connector (spec §4.4): the descriptor's host key is checked before any
  authentication; `passwd` runs in a PTY and the new password is sent only after the
  broker's commit; unrecognized prompts and rejected passwords are refusals; tested in CI
  against OpenSSH with linux-pam `passwd`.
- Enrollment and re-enrollment (spec §3.4, §4.5): the Control Plane reserves a version and
  the account's lock for an `enroll` transaction (restoring a displaced stuck rotation
  after 15 minutes or on failure), checks and relays the CLI's signed candidate; the broker
  checks it again, binds exactly once only after the Control Plane accepted, and commits
  `vault_commit` with `abort` (`superseded_by_reenrollment`) on every unterminated envelope,
  which is the only way out of quarantine.
- Checkout and leases (spec §3.4, §3.6): `vault_checkout` with a single-use challenge and a
  possession proof opens a lease, verifies the credential once and wraps it to the
  requester's key only; check-in or expiry starts the lease's cleanup rotation, the only
  rotation path until it releases; scheduled rotations wait; `manual_rotation` runs a
  rotation or re-arms a pending cleanup. `cli.NewTransaction`, `Proof` and `OpenDelivery`
  are the CLI's half.
- Inventory and attributes (spec §8.2, §10): admins add assets and accounts, set an
  account's owner and status, upload target descriptors (strictly decoded, 1A slice only,
  bound to this deployment, account and asset) and define account and user attributes
  (`string` or `enum`); SCIM-sourced attributes are read-only.
- Traffic-light scorecard (spec §8.1, §8.3): every active account is Green (scheduled and
  released at least once), Yellow (sealed current envelope) or Red, with one health value
  beside it; `GET /api/reports/scorecard` serves the dashboard and, with `format=json|csv`,
  an audited download of the same rows. Non-admins see accounts they own or are listed on.
- SCIM syncs `title` and the Enterprise User extension's `department` and `manager`
  into read-only user attributes (spec §8.2); deleting a SCIM user leaves its accounts
  unowned.

### Upgrade impact

- No KyGuard install exists yet, so nothing migrates. The replica configuration fingerprint
  no longer covers the removed `KY_SAML_*` settings.
- New binary `kyguard-cli` (`go build ./cmd/cli`); `golang.org/x/term` is a new direct
  dependency and `golang.org/x/crypto` becomes direct (Argon2id).
- Migration 100 adds the broker tables (`bootstrap_bundles`, `trust_manifests`,
  `broker_pools`, `brokers`, `pairing_tokens`, `operation_intents`); no data migrates.
  New settings `KY_BROKER_LISTEN` (default `:8443`), `KY_BROKER_HOSTNAME` (unset: listener
  off) and `KY_MIN_BROKER_VERSION` are shared replica settings; `github.com/coder/websocket`
  is a new dependency.
- Migration 101 adds `assets`, `accounts`, `target_descriptors`, `secret_envelopes`,
  `envelope_receipts`, `rotation_locks` and `rotation_runs`; no data migrates.
- Migration 103 adds `checkout_leases` and the relay mailbox columns of
  `access_transactions`; no data migrates.
- Migration 102 adds enrollment columns to `rotation_locks` and `access_transactions`; no
  data migrates.
- `github.com/go-ldap/ldap/v3` is a new dependency (the AD connector); CI gains a
  `connectors` job that runs Docker targets.
- New binary `kyguard-broker` (`GOOS=linux go build ./cmd/broker`); `go.etcd.io/bbolt` is a
  new dependency (the broker journal).
- The module declares `go 1.27.0` (for `crypto/mldsa`); builds need Go 1.27, as the pinned
  `go1.27.4` toolchain already provides.
- Migration 200 adds `attribute_definitions` and `attribute_values`; no data migrates.

## Maintaining notes

Before merging a change to `main`, replace Current source with its major changes and upgrade
impact. Include restart/rebuild requirements, schema/configuration or format migrations and
deprecated behaviour, and say explicitly when no migration is needed. Archive the previous
Current source summary under its known full commit after it has shipped.

`make notes-check` compares the current summary with `HEAD^`; for local review against the
target, run `python3 scripts/check-release-notes.py --base origin/main`. It checks presence
and freshness, not accuracy.
