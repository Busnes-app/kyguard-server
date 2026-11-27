# pqcrypto

## Purpose
KyGuard's wire format, crypto core and signed contracts, `docs/SPEC.md` §3. §3.1: strict
JSON field types, RFC 8785 JCS (`canonical/`), the domain digest `D(obj)`,
`HybridSig`/`HybridPub` (ML-DSA-65 + Ed25519), `sig_key_id`/`enc_key_id`, the payload and
DEK-wrap AADs, the HPKE DEK wrap, the AES-256-GCM payload and `opid`. §3.2–§3.5 and §3.7:
the signed header, the bundle and manifests (`manifests.go`, `trust.go`), transactions and
possession proofs (`tx.go`), envelopes (`envelope.go`) and receipts (`receipt.go`). Used by
the Control Plane, broker, offline utility and browser WASM client.

## Ownership
Owns every byte KyGuard signs, hashes or seals. The spec is normative; this package
implements it and `docs/DECISIONS.md` records where the spec left a choice.

## Local Contracts
- Stdlib crypto only (`crypto/mldsa`, `crypto/ed25519`, `crypto/hpke`, `crypto/aes`,
  `crypto/cipher`, `crypto/sha256`) plus `ky-primitives/recoverykey` for X-Wing keys. No
  third-party crypto, no custom primitives, no signer interface.
- Parse untrusted JSON only through `canonical.Decode`: it rejects duplicate keys,
  malformed UTF-8, lone surrogates, non-integer or unsafe numbers, unknown fields and any
  input whose typed re-encoding differs from its canonical form.
- Both signature halves are always checked; either failing rejects.
- `Trust` is the only way a manifest becomes trusted: `NewTrust` against the pinned
  fingerprint, then `Accept` in order. It holds state in memory; callers persist
  `Records()` and replay them. Broker journal state (leases, rotations, quarantine) stays
  out of this package; `VerifyTx`, `VerifyEnvelope` and `Append` take it as context.
- `New: true` in `EnvelopeContext`/`ReceiptContext` means new work (active signer, active
  recipients, persisted recovery epoch); `false` verifies history.
- Every error a vector names is a stable `Error`/`canonical.Error` code. Never rename one.
- Golden vectors live in `testdata/vectors/` and are written only by
  `go generate ./internal/pqcrypto` (deterministic: fixed seeds plus
  `testing/cryptotest.SetGlobalRandom`). Contract vectors share one deployment
  (`world_test.go`) and are consumed against `context.json` only. Generators state each
  verdict themselves; the consumers (`vectors_test.go`, `contracts*_test.go`) run the real
  code and must not share generator logic.
  The browser compiles the same implementation verified by the Go vectors.

## Work Guidance
- A wire change is a vector change: regenerate, review the JSON diff, and add a negative
  vector for each new refusal.

## Verification
- `go test -race ./internal/pqcrypto/...` (includes `TestVectorsCurrent`, which fails on
  stale vectors), also with `GODEBUG=fips140=on`.
- `go test -fuzz=FuzzParse ./internal/pqcrypto/canonical`

## Child DOX Index
None.
