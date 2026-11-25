# cptrust

## Purpose
The Control Plane's verified view of the Custodian-signed manifests (`docs/SPEC.md` §3.2,
§3.7): the imported bootstrap bundle plus every accepted manifest, persisted in
`trust_manifests` in acceptance order and replayed through `pqcrypto.Trust`.

## Ownership
Owns manifest admission on the Control Plane. Verification rules are `internal/pqcrypto`'s.

## Local Contracts
- `Submit` is the only way a manifest enters `trust_manifests`. It catches up from the
  database first, so replicas never fork the sequence; a write that loses the race
  (`store.ErrConflict`) rebuilds and retries once.
- `Submit` refuses a manifest over `MaxManifest` (512 KiB) before parsing it, so every stored
  manifest fits one broker channel frame (decision 61). The manifest API reads at most that.
- Equivocation is audited as `trust.equivocation` before the error returns.
- A failed replay or persist drops the cached state; the next call rebuilds it from the
  database. Never serve a partial replay.

## Verification
- `go test -race ./internal/cptrust/...` on SQLite and PostgreSQL.

## Child DOX Index
None.
