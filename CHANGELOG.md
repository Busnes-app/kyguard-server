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
- New binary `kyguard-broker` (`GOOS=linux go build ./cmd/broker`); `go.etcd.io/bbolt` is a
  new dependency (the broker journal).
- The module declares `go 1.27.0` (for `crypto/mldsa`); builds need Go 1.27, as the pinned
  `go1.27.4` toolchain already provides.

## Maintaining notes

Before merging a change to `main`, replace Current source with its major changes and upgrade
impact. Include restart/rebuild requirements, schema/configuration or format migrations and
deprecated behaviour, and say explicitly when no migration is needed. Archive the previous
Current source summary under its known full commit after it has shipped.

`make notes-check` compares the current summary with `HEAD^`; for local review against the
target, run `python3 scripts/check-release-notes.py --base origin/main`. It checks presence
and freshness, not accuracy.
