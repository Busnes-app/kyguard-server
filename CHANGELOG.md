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
  marked unverified) before applying a Custodian signature.

### Upgrade impact

- No KyGuard install exists yet, so nothing migrates. The replica configuration fingerprint
  no longer covers the removed `KY_SAML_*` settings.
- New binary `kyguard-cli` (`go build ./cmd/cli`); `golang.org/x/term` is a new direct
  dependency and `golang.org/x/crypto` becomes direct (Argon2id).
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
