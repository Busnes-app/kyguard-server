# connectors

## Purpose
The Phase 1A target connectors of `docs/SPEC.md` §4.4, each implementing
`broker.Connector`: `adldaps` (Active Directory over LDAPS, self-change of `unicodePwd`) and
`sshpasswd` (Linux over SSH, `passwd` in a PTY). `connectortest` runs real targets in Docker
for their tests.

## Ownership
Owns how a broker talks to a target. The rotation order, journaling and quarantine are
`internal/broker`'s; a connector only reports outcomes.

## Local Contracts
- Dial only the verified descriptor's host and port. TLS trusts only `tls_ca_pem` with the
  host as server name; SSH checks `ssh_host_key_sha256` in the host-key callback before any
  authentication. The `Dial` field exists for tests that map the descriptor host to a
  container; production leaves it nil.
- Every operation observes its context: cancellation or a deadline closes the target
  connection rather than waiting for the connector's fixed timeout.
- `Session.Change` calls `commit` immediately before the first byte of the new password
  leaves and sends nothing if it fails.
- Return `broker.ErrAuthFailed` only for a deterministic authentication failure and
  `broker.ErrRefused` only when the target is known unchanged. Everything else is ambiguous.
- `adldaps`: simple bind only (empty passwords refused), LDAPS only, TLS 1.2 minimum;
  baseline is `pwdLastSet` and `msDS-KeyVersionNumber`; verify is a fresh bind plus
  `pwdLastSet` advancing; LDAP 49 is `ErrAuthFailed`, 19 and 53 on the modify are
  `ErrRefused`; `PasswordAge` reads `pwdLastSet` and the minimum age of the account's
  resultant PSO (`msDS-ResultantPSO`), failing if that PSO is unreadable, or the domain
  `minPwdAge` when there is none (DECISIONS 65).

## Verification
- `KY_TEST_DOCKER=1 go test -race ./internal/connectors/...` (CI job `connectors`; on Major
  under `kslot`). Without `KY_TEST_DOCKER` the Docker tests skip.
- The Samba image (`adldaps/testdata/samba`) uses the test's own CA, turns off Samba's
  hour-long acceptance of the previous password and counts bad passwords.

## Child DOX Index
None.
