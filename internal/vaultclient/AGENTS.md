# Vault client

## Purpose

Shared browser-safe vault operations and KyIdentity app-subkey handoff.

## Ownership

Owns encrypted user key bundles and assembly of signed requests. Signed wire
formats and validation belong to `internal/pqcrypto`.

## Local Contracts

- [Spec §10.1](../../docs/SPEC.md#101-browser-vault) defines bundle format, identity
  binding and separate browser origin. Build the package for both native tests and
  Go WASM. Keep it free of dependencies on storage, HTTP listeners or server secrets.
- KyIdentity interop uses X-Wing and the authenticated OAuth transcript. The
  published upstream fixture in `testdata/kyidentity-handoff.json` is synthetic.
- Only the browser calls bundle sealing and opening. The API validates the shape,
  signed enrollment and ownership, then stores ciphertext.

## Verification

- `go test -race ./internal/vaultclient`
- `make build-browser-vault` compiles the browser consumer.

## Child DOX Index

None.
