# KyGuard

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/17119/badge)](https://www.bestpractices.dev/projects/17119)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Busnes-app/kyguard-server/badge)](https://scorecard.dev/viewer/?uri=github.com/Busnes-app/kyguard-server)

KyGuard is a self-hosted privileged access management (PAM) and just-in-time access platform
for the Busnes.app suite. This repository ships the Control Plane (`kyguard-server`); the
Resource Broker (`kyguard-broker`) and `kyguard-cli` follow. It is built on `ky_server_base`:
Go backend, embedded React PWA, SQLite or PostgreSQL, federated sign-in (KySignOn, OIDC),
SCIM provisioning, and disaster recovery through the suite's KyRecovery.

The design is [docs/SPEC.md](docs/SPEC.md) (v2.4). Only its Phase 0 and Phase 1A sections are
being built; until they land, much of what the spec describes does not exist yet.

Published image (Docker Compose 2.24.0 or later):

```bash
make ci        # gofmt, vet, race tests, smoke test
make run       # build and start on :8080 (no account exists; see First sign-in)
docker compose up -d
```

Source install (never paste this into a published-image install: the build overlay wins over a
`KY_IMAGE` digest pin, and a source install must set this line before its first `up -d` on a
new checkout; an install from before the published image existed has no such line yet, so run
this block once and confirm with `docker compose config --images`, which must print
`kyguard-server:local` rather than the `ghcr.io` name):

```bash
make ci        # gofmt, vet, race tests, smoke test
make run       # build and start on :8080 (no account exists; see First sign-in)
(umask 077; t=$(mktemp ./.env.XXXXXX) && touch .env \
  && cf=$({ grep '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } | tail -n1 | cut -d= -f2-) && cf=${cf:-docker-compose.yml} \
  && case ":$cf:" in *:docker-compose.build.yml:*) ;; *) cf="$cf:docker-compose.build.yml";; esac \
  && { grep -v -e '^COMPOSE_FILE=' .env || [ $? -eq 1 ]; } > "$t" \
  && printf 'COMPOSE_FILE=%s\n' "$cf" >> "$t" && mv "$t" .env)
docker compose up -d
```

Read the [release notes](CHANGELOG.md) for the selected source revision and every
intervening release before upgrading; they describe migrations and upgrade impact.

Update a published-image install on the rolling tag:

```bash
docker compose pull && docker compose up -d
```

A digest-pinned install (`KY_IMAGE` in `.env`) gets nothing from `pull`: re-run the pin recipe in
`docker-compose.yml` with the commit sha you want first, or delete that line to follow `:latest` again.

`AGENTS.md` is the contract for working in this repository. [CONTRIBUTING.md](CONTRIBUTING.md) has
the process, test policy and coding standard, and [docs/ASSURANCE-CASE.md](docs/ASSURANCE-CASE.md)
the threat model, trust boundaries and why the security requirements hold.

[External interface reference](docs/INTERFACES.md) documents HTTP routes, request and
response fields, authentication/CSRF, SCIM limitations, CLI commands and environment
configuration. It describes the implemented interfaces.

[Strong-key/TLS configuration](docs/STRONG-CRYPTO.md) describes the optional
production profile, Compose overlay and migration for existing signing secrets
and IdP keys. Encryption/recovery keys and stored records stay in place.

## SQLite, PostgreSQL and replicas

SQLite remains the single-server default. [Replication and migration](docs/REPLICAS.md)
explains database-backed security, automatic scheduled-worker election, the verified
`migrate-postgres` maintenance command, `/livez` and `/readyz`, the shared-configuration
check and the tested Compose replica overlay (`docker-compose.replicas.yml`, HAProxy).
Kubernetes is optional. Both drivers seal the same recovery capsules. Application replicas
do not make PostgreSQL highly available.

## First sign-in

KyGuard has no bootstrap admin. Users sign in through SSO; local sign-in exists only for up to
five break-glass administrators, created on the host:

```bash
kyguard-server break-glass create -username <name>   # Compose: docker compose exec app /app/kyguard-server break-glass create -username <name>
```

It prints a generated password and a TOTP provisioning URI once; store both offline. A
break-glass sign-in needs the password and a current code together, lasts 30 minutes, asks
for a reason before its first privileged action and is audited as critical. Replace a lost
authenticator with `kyguard-server break-glass reset-totp -username <name>`, which also ends
the account's sessions.

## License

KyGuard is released under the [MIT License](LICENSE.txt).

[![OctoCounts](https://api.octocounts.com/badge/Busnes-app/kyguard-server/branch/main)](https://octocounts.com/github/Busnes-app/kyguard-server/tree/main)

## Documentation

- [Container networking](docs/CONTAINER-IP.md) — give the app a static IP on the Docker network. <a id="container-ip-address"></a>
- [Backups and disaster recovery](docs/DISASTER-RECOVERY.md) — sealed backup capsules, KyRecovery pairing, every `KY_BACKUP_*` variable and the LAN DNS override. <a id="disaster-recovery"></a><a id="two-ways-to-get-a-key"></a><a id="why-tls-matters-here"></a><a id="one-run-every-destination"></a><a id="environment"></a><a id="upgrading-from-plaintext-local-backups"></a><a id="restoring"></a>
- [Interfaces](docs/INTERFACES.md) — the HTTP, command-line and environment reference.
- [Restore](docs/RESTORE.md) — bring a server back from a recovery capsule.
- [Strong keys](docs/STRONG-CRYPTO.md) — the supported strong-key configuration.
- [Assurance case](docs/ASSURANCE-CASE.md) — threat model, trust boundaries, and why the security requirements are met.
- [Contributing](CONTRIBUTING.md) — how to propose a change and what it must pass.
- [Security policy](SECURITY.md) — how to report a vulnerability privately.
- [Release notes](CHANGELOG.md) — what changed in each release, and its upgrade impact.
