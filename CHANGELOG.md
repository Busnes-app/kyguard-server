# Release notes

[Overview](README.md) · [Restore and image verification](docs/RESTORE.md) · [Design spec](docs/SPEC.md)

## Reading a release

KyGuard distributes rolling containers identified by their full source commit, not SemVer
tags. For a published `:<commit>` image, read **Current source** in this file at that exact
commit: `https://github.com/Busnes-app/kyguard-server/blob/<commit>/CHANGELOG.md#current-source`.
History before the KyGuard import is `ky-server-base` at `fed0fb3` and its own `CHANGELOG.md`.

## Current source

### Changes

- Restore contract (spec §9.4): capsules carry the internal broker CA (`data/broker-ca.key`,
  `data/broker-ca.crt`) when present, and refuse to seal half of it; `restore` also deletes CLI
  login codes and unconsumed broker pairing tokens. The recovery-manifest seal gate is not in this
  release.
- Durable intents for external effects (spec §9.3): a KyRecovery pairing claim, a recovery-key
  pin and a deposit each commit an `operation_intents` row (migration 16) before they start; the
  audit record is the completion append, so a failed audit write now answers 500 instead of
  being logged. Startup settles what a stopped process left (`outcome_unknown`), and a later
  deposit supersedes it. The exempt-network list commits with its audit record; a capsule
  export sends nothing without its record.
- Chained audit log (spec §9.3): every audit record carries `seq`, `prev_hash` and an HMAC
  `hash` under a key derived from `data/encryption.key`, with the anchor in `audit_chain_head`
  (migration 15). One writer appends inside the caller's transaction, so a failed audit write
  rolls the change back; SQLite transactions now begin immediate. No audit result is
  discarded any more. Records from before the chain are chained when the store opens, and
  verification rejects a stored field that differs from its hashed form.
- Route registry (spec §7.5): every main-mux route is registered with a class through one
  function, and a test fails on any route outside it. Backup actions need a step-up within five
  minutes (a code at `/api/auth/stepup/totp` refreshes it). Administrators can reset an SSO
  user's factor with a fresh code of their own (`DELETE /api/admin/users/{id}/factor`).
- TOTP step-up after every SSO sign-in (spec §7.3): the callback issues a five-minute pending
  session limited to `/api/auth/me`, logout and `/api/auth/stepup/*`; a TOTP code exchanges it
  for a new 12-hour active session bound to the same login. First-factor enrollment
  (`/api/auth/stepup/enroll`, `/enroll/confirm`) needs an ID token that asserted MFA. The web
  shell shows a step-up screen. Migration 14 (`kyguard_pending_sessions`).
- SSO identity is `(issuer, subject)` (spec §7.2): `users.sso_issuer` with a unique index,
  sessions record their issuer, and both back-channel logout fences are keyed by issuer.
  SCIM accounts take `KY_SCIM_ISSUER` (default `KY_KYSIGNON_ISSUER`).
- Generic OIDC sign-in at `/api/sso/oidc/login` and `/callback`. Both providers send
  `max_age=0` (and `acr_values` for an MFA acr set, `KY_OIDC_MFA_ACRS` for OIDC) and refuse an
  ID token whose `auth_time` is missing or older than 120 seconds.
- The role comes only from the per-app `roles` claim at every sign-in; the IdP-wide `role`
  fallback is gone. SCIM never grants admin; `KY_SCIM_ALLOW_ADMIN` is removed.
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
- Schema migration 12 (`kyguard_local_factors`): `users.account_type`, `sessions.stage`,
  `stepup_at`, `break_glass_reason`, and the `mfa_factors` and `totp_attempts` tables, both
  carried by `migrate-postgres` and PostgreSQL snapshots. Migration 13 (`kyguard_sso_issuer`)
  adds the issuer columns and replaces the fence tables.
- KyGuard `internal/pqcrypto` wire format (spec §3.1): strict RFC 8785 JCS, decimal-string
  counters capped at 2^63-1, unpadded base64url, the domain digest `D(obj)`, ML-DSA-65 +
  Ed25519 hybrid signatures, `sig_key_id`/`enc_key_id`, the payload and DEK-wrap AADs, the
  X-Wing HPKE DEK wrap, the AES-256-GCM payload and `opid`, with committed golden vectors.

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
