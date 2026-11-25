# Build decisions

Readings of `docs/SPEC.md` taken during the Phase 0/1A build where the spec is silent or
contradicts itself. Each names its section. The most secure reading wins.

1. §13 Phase 0, §7.4 (bootstrap removal order). `ensureBootstrapAdmin` and `init-admin` are
   removed in the same PR that adds `kyguard-server break-glass create`. Removing them first
   would leave no way to create an admin, and the smoke, Docker, browser and replica CI jobs
   all sign in as one.
2. §7.2 (SAML removal). `/saml/*` is registered as an explicit 404 rather than deleted
   outright, because the SPA fallback answers every unknown non-API path with 200
   (acceptance test 15 requires 404).
3. §13 Phase 0 (rename). The SQLite file stays `ky_server.db` and the PostgreSQL role and
   database stay `ky_server`: the capsule member path `data/ky_server.db` is part of the base
   restore contract. The inherited `ky_server_base:` domain-separation labels (sealed
   KyRecovery token, replica fingerprint) stay, so the base's pinned fixtures keep proving
   the format.
4. §7.4 (break-glass password). `break-glass create` generates the password (24 characters,
   144 bits) and prints it once with the TOTP URI, rather than reading one from argv (visible in
   process listings) or a terminal. The holder may change it with password + code.
5. §7.4 (403 versus 401). A wrong password answers 401 for every account, so the 403 for an SSO
   account comes only after its password verifies; SSO accounts have no password, so the 403
   cannot enumerate them.
6. §7.4 (break-glass reason). The reason is stored on the session (`sessions.break_glass_reason`),
   set once through `POST /api/auth/break-glass/reason`, and checked by the admin middleware.
7. §7.3 rule 4 (factor binding). The sealed TOTP secret carries its user ID inside the sealed
   bytes, so a `secret_enc` copied onto another user's row does not open.
8. §7.3 rule 5 (counting). Each code attempt is inserted and committed before it is counted, and
   released only on success, so concurrent guesses can only both be refused, never both admitted
   past the limit.
9. §7.2 (SCIM admin refusal). "`checkRole` refuses `admin` unconditionally" is read as: no
   setting can let SCIM grant admin. SCIM may still update, deactivate or demote an account
   that already holds admin from its last sign-in; refusing every write that names admin would
   block deprovisioning an administrator through the directory.
10. §7.2 (SCIM issuer). "The configured SCIM issuer" is `KY_SCIM_ISSUER`, defaulting to
   `KY_KYSIGNON_ISSUER`, because KyIdentity is both the SCIM source and the KySignOn issuer.
11. §7.2 (auth_time). An `auth_time` more than one minute in the future is refused like a stale
   one; the spec states only the 120-second age limit.
12. §7.2 (legacy identities). A database with SSO subjects but no issuer (rows from before
   migration 13) is refused at startup with instructions to set `users.sso_issuer`, rather than
   guessing an issuer. No KyGuard install predates the migration.
12a. §7.2 (fence migration). Migration 13 replaces the sid- and provider-keyed fence tables with
   issuer-keyed ones instead of converting rows: fences live ten minutes and no KyGuard
   install exists.
