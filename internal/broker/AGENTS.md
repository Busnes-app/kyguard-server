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
- Rotation (`machine.go`, §4.2–§4.4): journal `reserving` → reserve → seal and sign `P_new` → journal `prepared`
  → store the envelope → log in with `P_old` and read the baseline → inside
  `Session.Change`'s commit callback journal the intent, wait for the Control Plane
  acknowledgement (`AckTimeout`, 30 s) and journal `ack_received` → the write. After the
  connection closes, the one `P_new` probe is journaled before it is sent; anything but
  success quarantines. There is no timer abort and no abort after `ack_received`.
- `Recover` (startup, every reconnect): `reserving` → reserve again under the same operation
  ID and abort it (a refusal means nothing was reserved); no `ack_received` → `abort` (`restart_before_send`);
  `ack_received` → `write_outcome_unknown` and the one probe; a recorded probe without a
  result → quarantine; journaled receipts not acknowledged → re-sent; a health report
  not acknowledged (`Account.Unreported`) → re-sent. It never writes.
- Health changes only through `setHealth`, which sets `Unreported` in the same journal save;
  only an acknowledged `report` clears it (DECISIONS 73).
- A run with unacknowledged receipts is never replaced: `start` re-sends them first and
  returns `ErrBlocked` if that fails (DECISIONS 63).
- `Sync` accepts manifests only through `Trust.Accept` (rollback and forks alerted, never
  applied), descriptors only if their policy pins the digest, and chains only if they
  verify and extend the broker's copy.
- Scheduler (`schedule.go`, §3.4, §4.4): `Tick` evaluates each account's signed schedule by
  the broker's clock and runs only the latest outstanding occurrence (due in the past and
  after the floor `max(last consumed due, policy persisted at, current commit)`). An
  occurrence is consumed only by `release`. A refused attempt sets
  `next_attempt_at = max(min-age deadline, now + interval)`; three refusals stop the account
  until a new policy epoch. A minimum age above the interval runs nothing
  (`schedule_below_min_age`). Nudges only call `Tick` early; `Schedule` also ticks every
  minute without them.
- Enrollment (`enroll.go`, §4.5): `Enroll` refuses before journaling or touching a target
  anything `VerifyTx` (enrollers, replay, versions, candidate digest) or `VerifyEnvelope`
  (`New`, with the transaction) refuses, and an open rotation on a healthy account. Then:
  journal candidate and transaction → Control Plane `accept` (without it, fail and never
  bind) → journal `accept_ack` and burn `request_id` together → journal verify-start → one
  login → commit (abort `superseded_by_reenrollment` on every unterminated envelope, the
  stuck run's included, plus `vault_commit`) or fail (abort `enrollment_failed` on the
  candidate only). A restart never binds twice. An open enrollment blocks rotation; its
  journaled, unacknowledged receipts are re-sent by every `Tick` (and `Recover`), never
  verifying again (DECISIONS 68).
  Lease reset evidence (§4.5 step 3) arrives with checkout leases.
- Checkout and leases (`lease.go`, §3.6): `Tx` verifies a relayed `vault_checkout` or
  `manual_rotation` against the journal state. Checkout journals only a single-use
  challenge; `Proof` re-verifies the transaction and the possession proof, then in one
  journal write burns `request_id`, consumes the challenge and opens the lease, and only
  then unwraps, verifies the credential once and wraps the DEK to `enc_key_id`. A denied
  verification delivers nothing, closes the lease and quarantines. Check-in (proof from
  the same `cnf_pub`) or expiry moves the lease to `rotation_pending`; its cleanup
  rotation (`opid(request_id, attempt)`) is then the only rotation path, refusals retry at
  `max(min-age deadline, now + 1 h)` without a stop, and only `release` closes the lease.
  Scheduled occurrences wait while a lease is open. `manual_rotation` re-arms an idle
  cleanup, is refused during an active lease, resets the refusal counter and waits for
  the minimum age. Every lease state is mirrored to `checkout_leases`; a new lease must be
  mirrored before the credential is unwrapped, and a lease whose last state is not
  acknowledged is never replaced. The checkout wrap is journaled until delivered; `flush`
  (every tick and `Recover`) re-sends both.
- Target change (§3.3): a lease keeps its policy and descriptor digests, and its cleanup runs
  only at that descriptor. `deferPolicy` holds a descriptor-changing policy in
  `Account.DeferredPolicy` while the lease is open; `applyDeferred` accepts it once closed.
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
