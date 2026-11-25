# Build decisions

Readings of `docs/SPEC.md` taken during the Phase 0/1A build where the spec is silent or
contradicts itself. Each names its section. The most secure reading wins.

1. §13 Phase 0, §7.4 (bootstrap removal order). The scaffold PR leaves `ensureBootstrapAdmin`
   and `init-admin` in place; the break-glass PR removes them together with adding
   `kyguard-server break-glass create`. Removing them first would leave no way to create an
   admin, and the smoke, Docker, browser and replica CI jobs all sign in as one.
2. §7.2 (SAML removal). `/saml/*` is registered as an explicit 404 rather than deleted
   outright, because the SPA fallback answers every unknown non-API path with 200
   (acceptance test 15 requires 404).
3. §13 Phase 0 (rename). The SQLite file stays `ky_server.db` and the PostgreSQL role and
   database stay `ky_server`: the capsule member path `data/ky_server.db` is part of the base
   restore contract. The inherited `ky_server_base:` domain-separation labels (sealed
   KyRecovery token, replica fingerprint) stay, so the base's pinned fixtures keep proving
   the format.
4. §3.1 (JSON numbers). Signed objects allow only integers in [-(2^53-1), 2^53-1], with no
   fraction, exponent or `-0`; in that range RFC 8785 number serialization is plain decimal
   in every runtime. Counters stay decimal strings (rule 2).
5. §3.1 rule 1 (strict typed decoding). A received object must re-encode from its typed form
   to the same JCS bytes as its input. This rejects unknown fields, case-variant keys (Go's
   `encoding/json` matches keys case-insensitively), explicit empty values for omitted
   fields and `null` in place of a value.
6. §3.1 rule 3 (timestamps). The one accepted form is `YYYY-MM-DDTHH:MM:SSZ`: UTC, whole
   seconds, no fraction, so the JCS bytes are identical across runtimes.
7. §3.1 rule 3 (base64url). Padding, the standard alphabet, non-zero trailing bits and
   embedded CR or LF are rejected. Go's decoder skips CR/LF even in strict mode, so they are
   refused first.
8. §3.1 rule 4 (`D(obj)`). Only the top-level `signatures` and `approvals` members are
   removed; nested objects keep theirs, so `bootstrap_fingerprint` covers the signatures of
   the bundled manifests. `<type>` must match `^[a-z][a-z0-9_]*$`.
9. §3.1 (AAD field checks). The AAD builders refuse an `envelope_kind` other than
   `managed`/`vaulted`, a `recipient_type` other than `broker`/`user`/`recovery`, and a
   `recipient_id` without that type's form (UUID for broker and user, 64-hex for recovery).
   `WrapDEK` and `UnwrapDEK` refuse an AAD whose `key_id` is not the `enc_key_id` of the key
   in use.
10. §3.4 (`opid`). The first 16 digest bytes are formatted `8-4-4-4-12` lowercase hex with no
    UUID version or variant bits forced; the spec says only "formatted as a UUID", and
    forcing bits would discard digest entropy.
