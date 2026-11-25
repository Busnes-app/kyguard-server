# cli

## Purpose
`kyguard-cli` (`cmd/cli` is the thin `main`): offline deployment init, trust pinning,
manifest import, user key enrollment and Custodian signing (`docs/SPEC.md` §2, §3.2,
§3.3). Every user-side key and signature lives here; the Control Plane is never trusted.

## Ownership
Owns the CLI commands, the key-file format and the persisted trust state. Crypto and
verification rules are `internal/pqcrypto`'s; this package must not re-implement them.

## Local Contracts
- Trust state is `$KYGUARD_HOME/trust.json` (default `<user config dir>/kyguard`, 0700
  dir, 0600 file, atomic rename): the pinned fingerprint, the verified bundle and every
  accepted manifest in order. `loadTrust` replays it through `pqcrypto.NewTrust` and
  `Accept`, so the high-water mark per `(type, scope.id)` survives restarts. Without it,
  every command that reads manifests or keys returns `ErrNotPinned`.
- Any future command that opens a secret must call `loadTrust` first.
- `trust` refuses a different pin unless `--replace` (custodian quorum loss, §3.2 rule 5).
- `sign` refuses a draft for another deployment, an epoch below the verified one, a
  same-epoch fork, a key outside the current custodian set and a managed policy without a
  matching target descriptor. It prints Control Plane labels quoted and marked
  UNVERIFIED, and resolves principals only from verified key enrollments.
- Key files are written with `keyfile.Store` (0600, never replaced) and read with
  `keyfile.ReadPrivate`. Seeds are AES-256-GCM sealed under Argon2id
  (`password.DefaultParams`); the clear header (kind, ID, key IDs, KDF) is the AAD.
- `Client` is the only way to the Control Plane. `kyguard-cli login` (§7.6, owned by the
  auth work) supplies the session-backed implementation; until then commands take files.

## Verification
- `go test -race ./internal/cli/...`

## Child DOX Index
None.
