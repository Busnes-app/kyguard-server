# brokerproto

## Purpose
The broker listener of `docs/SPEC.md` §4.1, shared by `kyguard-server` and
`kyguard-broker`: the internal broker CA (`ca.go`), both TLS configurations (`tls.go`),
pairing tokens and wire messages (`messages.go`), the listener handler (`listener.go`) and
the broker-side pairing and channel client (`client.go`).

## Ownership
Owns `/broker/v1/*`. It is never mounted on the main mux. Signed-object rules are
`internal/pqcrypto`'s; the Control Plane's verified manifests come from `internal/cptrust`.

## Local Contracts
- The CA authenticates; it never authorizes. The channel admits a broker only when its
  verified internal-CA certificate's `urn:uuid:<broker_id>` names a paired broker and the
  current manifest of that broker's pool lists it `active` with the certificate's SHA-256 as
  `mtls_cert_sha256`. Pairing alone admits nothing.
- Listener and broker client: TLS 1.3 with `X25519MLKEM768` only via `pqtls.HybridOnly`
  (no classical fallback, DECISIONS 81). Listener uses `VerifyClientCertIfGiven` against
  the CA; the leaf is issued for `KY_BROKER_HOSTNAME` at every start and carries the CA in
  its chain.
- Brokers pin the CA by SHA-256 and the hostname from the token URL. `ClientTLS` replaces
  Go's verification with `VerifyConnection`; never return its config with the callback
  removed.
- A pairing token is one-time, 10 minutes, stored as `HashSecret`. A claim consumes the
  token, stores the broker and a `pending` pairing intent in one transaction; the intent ends
  `complete` only if the response was written and flushed, otherwise `outcome_unknown`
  (audited). Never re-deliver a lost pairing response.
- One channel per broker: a reconnect replaces the map entry under the listener lock and
  closes the old connection after unlocking. Never block (a close handshake, a write) while
  holding it.
- Channel RPC (`rpc.go`, `vault.go`): broker requests carry an ID and get one `result`;
  Control Plane pushes carry ID 0. Signed objects travel as base64url of their canonical
  bytes. Every request re-checks that the broker is its pool's active member and that the
  account's current managed policy names that pool. The Control Plane verifies every
  envelope (`New: true`, signed by this broker, a rotation envelope) and every new receipt
  (`Trust.Append`, `New: true`, the request's operation) before storing it, and derives the
  current envelope, run state and lock release from the verified receipts alone, never
  from the broker's word. Refusals are stable codes (`locked`, `conflict`, pqcrypto codes).
- Frames are at most `MaxFrame` (4 MiB) on both ends. `sync` reads and sends at most
  `SyncPage` manifests within `SyncBudget` encoded bytes, always one (a manifest is at most
  `cptrust.MaxManifest`), and lists the pool's accounts on the last page. `sync_account`
  pages, from `from` in version order, the open chains at or below the broker's version and
  then every newer one: at most `SyncChains` and, descriptor included, `SyncBudget`, always
  one chain (the store caps a chain at `store.MaxChain` and a descriptor at
  `store.MaxDescriptor`). Never return or read a whole history for one request: use
  `OpenChains`, `ChainsAfter`, `Chain` and `ManifestsPage`, never `Chains` (decision 62).
- The reader never blocks on `Pushes`: a push that finds the queue full is dropped
  (decision 70).
- Pushes to a broker go through `Listener.Relay`: this replica's channel if it holds one,
  else `broker_outbox`, drained by the replica that does (decision 75). Never answer a
  relay with "not connected" just because this replica lacks the channel.
- Enrollment: `accept` is the §4.5 acceptance CAS; `enroll` is a push of the relayed
  transaction and candidate. A receipts request ending an enrollment releases its lock by
  `vault_commit` (delete) or `enrollment_failed` (restore the displaced holder).
- `CreateCA` never replaces existing files; `LoadCA` refuses a key that is not the
  certificate's.

## Verification
- `go test -race ./internal/brokerproto/...`, also with `GODEBUG=fips140=on`.

## Child DOX Index
None.
