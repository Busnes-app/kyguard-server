# broker

## Purpose
`kyguard-broker` (`cmd/broker` is the thin `main`), `docs/SPEC.md` §4: the broker's key
file, its bbolt journal (§3.7), pairing (§4.1 steps 2–4) and the daemon that holds the
control channel. Later work adds the scheduler, rotation machine, connectors and leases.

## Ownership
Owns everything that runs on a broker host. Signed-object rules are `internal/pqcrypto`'s;
the wire and TLS are `internal/brokerproto`'s.

## Local Contracts
- `broker.key` (`KeyFile`) holds four 32-byte seeds (TLS Ed25519, ML-DSA-65, Ed25519,
  X-Wing), written once with `keyfile.Store` (0600) and refused by `LoadKeys` if anyone but
  the owner can read it. `openKeys` is the one function allowed to rebuild the X-Wing key
  (`TestNothingInTheServerDecrypts`).
- `journal.db` (`JournalFile`) is bbolt, 0600, with its exclusive file lock (a second open
  fails after 1 s). It holds no plaintext credential. Pairing is recorded once.
- `pair` refuses an already-paired journal, takes exactly one of
  `--bootstrap-fingerprint` and `--bootstrap-bundle`, reuses an unpaired key file, and
  prints `broker_id`, `sig_key_id`, `enc_key_id` and `cert_sha256` for the Custodians.
- Nudges carry no authority or content; `App.Nudges` only wakes the scheduler.
- `cmd/broker` sets `RLIMIT_CORE=0` before anything else. `deploy/broker/kyguard-broker.service`
  is the systemd unit (`LimitCORE=0`, `UMask=0077`, sandboxing).

## Verification
- `go test -race ./internal/broker/... ./cmd/broker/...`

## Child DOX Index
None.
