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
- Journal buckets (`state.go`): `manifests` (acceptance order; `Journal.Trust` replays them
  from the pinned bundle), `descriptors` (by digest) and `accounts` (one JSON `Account` per
  account: the chain copy of §3.7, the version high-water mark, health, quarantine, schedule
  floor inputs and the latest `Run`). Every `Save` is one fsynced bbolt transaction.
- Rotation (`machine.go`, §4.2–§4.4): reserve → seal and sign `P_new` → journal `prepared`
  → store the envelope → log in with `P_old` and read the baseline → inside
  `Session.Change`'s commit callback journal the intent, wait for the Control Plane
  acknowledgement (`AckTimeout`, 30 s) and journal `ack_received` → the write. After the
  connection closes, the one `P_new` probe is journaled before it is sent; anything but
  success quarantines. There is no timer abort and no abort after `ack_received`.
- `Recover` (startup, every reconnect): no `ack_received` → `abort` (`restart_before_send`);
  `ack_received` → `write_outcome_unknown` and the one probe; a recorded probe without a
  result → quarantine; journaled receipts not acknowledged → re-sent. It never writes.
- `Sync` accepts manifests only through `Trust.Accept` (rollback and forks alerted, never
  applied), descriptors only if their policy pins the digest, and chains only if they
  verify and extend the broker's copy.
- `Machine.Hook` is a test-only crash point; it must never be set in production.
- Connectors implement `Connector`/`Session` (`connector.go`); `ErrAuthFailed` and
  `ErrRefused` are the only deterministic outcomes, any other error is ambiguous.
- `cmd/broker` sets `RLIMIT_CORE=0` before anything else. `deploy/broker/kyguard-broker.service`
  is the systemd unit (`LimitCORE=0`, `UMask=0077`, sandboxing).

## Verification
- `go test -race ./internal/broker/... ./cmd/broker/...`
  `TestDisableCoreDumpsUnderTheUnit` runs the startup step under the unit's real sandbox
  through `systemd-run --user`; it skips without a user manager, so run it on a systemd host
  whenever the unit's `[Service]` lines change.

## Child DOX Index
None.
