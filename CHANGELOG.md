# Release notes

[Overview](README.md) · [Restore and image verification](docs/RESTORE.md) · [Design spec](docs/SPEC.md)

## Reading a release

KyGuard distributes rolling containers identified by their full source commit, not SemVer
tags. For a published `:<commit>` image, read **Current source** in this file at that exact
commit: `https://github.com/Busnes-app/kyguard-server/blob/<commit>/CHANGELOG.md#current-source`.
History before the KyGuard import is `ky-server-base` at `fed0fb3` and its own `CHANGELOG.md`.

## Current source

### Changes

- Break-glass accounts (spec §7.4): `kyguard-server break-glass create -username NAME` makes a
  local administrator with a generated password and TOTP secret, printed once; at most five
  exist. `break-glass reset-totp` replaces a secret and ends the account's sessions.
- `POST /api/auth/login` accepts only break-glass accounts, and only with `totp_code` in the
  same request; an SSO account gets 403 even with a correct password. The code is checked only
  after the password, is single-use, and fails past 10 failed codes per user per 15 minutes.
  Every attempt is a critical audit record.
- A break-glass session lasts 30 minutes without sliding and must record a reason
  (`POST /api/auth/break-glass/reason`) before any administrator route; the web shell shows a
  persistent banner and asks for it. Password changes need a TOTP code; passwords need 16
  characters.
- Removed the bootstrap admin (`KY_ADMIN_PASSWORD`) and `init-admin`. An unknown subcommand
  now exits 1 instead of starting the server.
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

### Upgrade impact

- No KyGuard install exists yet, so nothing migrates. The replica configuration fingerprint
  no longer covers the removed `KY_SAML_*` settings.
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
