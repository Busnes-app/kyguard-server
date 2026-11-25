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
- Listener: TLS 1.3, `VerifyClientCertIfGiven` against the CA, `X25519MLKEM768` then
  `X25519`. The leaf is issued for `KY_BROKER_HOSTNAME` at every start and carries the CA in
  its chain.
- Brokers pin the CA by SHA-256 and the hostname from the token URL. `ClientTLS` replaces
  Go's verification with `VerifyConnection`; never return its config with the callback
  removed.
- A pairing token is one-time, 10 minutes, stored as `HashSecret`. A claim consumes the
  token, stores the broker and a `pending` pairing intent in one transaction; the intent ends
  `complete` only if the response was written and flushed, otherwise `outcome_unknown`
  (audited). Never re-deliver a lost pairing response.
- `CreateCA` never replaces existing files; `LoadCA` refuses a key that is not the
  certificate's.

## Verification
- `go test -race ./internal/brokerproto/...`, also with `GODEBUG=fips140=on`.

## Child DOX Index
None.
