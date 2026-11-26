# Auth

## Purpose
Manages user authentication, password policies, session token lifecycle, local TOTP step-up, client addresses for rate limits, and anti-abuse CAPTCHA (Proof-of-Work default).

## Ownership
Owns session issuance and verification, the client-address helpers, and PoW challenge generation and verification.

## Local Contracts
- Sessions for `must_change_password` users authenticate only GET `/api/auth/me` and POST `/api/auth/change-password` or `/api/auth/logout`; private settings and product actions fail closed. Session issuance is bound to the verified password hash and serialized with replacement.
- Passwords (break-glass accounts only) require at least 16 characters (`ValidatePassword`).
- `Factors.Check` (`totp.go`) is the one TOTP check: it reserves an attempt (`totp_attempts`, committed before counting), refuses past 10 per user per 15 minutes or 5 per session (deleting that session at its fifth), opens the secret (sealed with its user ID), and spends the counter by CAS on the factor ID, which it returns. Every refusal is `ErrCodeRejected`. A session it authorizes carries that ID (`store.Session.FactorID`): `CreateSession` re-checks it under the user-row lock that `ReplaceFactor` (new ID on every reset) also takes, so a reset racing a sign-in leaves no session. A session's success audit record (`store.Session.Audit`) commits in the session's transaction, and cookies are set only after it. `IssueBreakGlassSession` issues a 30-minute, non-sliding, stepped-up session.
- `Session.CreatedAt` is the credential time. `IssueSession` stamps now.
- `IssueSSOSession` stores the provider's `sid` and dates the session by the ID token's `iat`, so back-channel logout by `sid` or by subject can end it; it fails with `store.ErrSSOSessionEnded` when that login was already ended.
- Active sessions are stored with SHA-256 hashed tokens and verified against secure HttpOnly / SameSite cookies or Bearer headers.
- `CookieName` names every cookie the server sets or reads: with `HostCookies` (an https `KY_APP_URL`, whose cookies are always Secure) it adds the `__Host-` prefix (Secure, `Path=/`, no Domain), so a sibling subdomain cannot plant a session, CSRF or SSO state cookie; bare names are then never read. `ValidateCSRF` takes the same flag.
- Session authentication rejects inactive accounts and deletes their presented session.
- PoW solutions must carry unexpired server-signed challenge metadata. `VerifyPoWSolution` with a `PoWSpent` set accepts each solved salt once until it expires; salts are recorded only after the signature and work check out, and expired ones are pruned whenever the set has doubled; there is no cap that would let a solution through unrecorded.
- `CheckPoWSolution` validates signed work without spending it; PostgreSQL API handlers
  spend the returned salt atomically in shared storage. SQLite retains `PoWSpent`.
- The default puzzle size is `config.DefaultPoWDifficulty`, measured so the browser's median solve is about one second; re-measure before changing it.
- KyGuard reverses the base rule that retired local MFA (spec §7.1). Local TOTP is the break-glass second factor (§7.4) and the step-up factor after every SSO login and before privileged actions (§7.3). Factors live in `mfa_factors`, sealed under `data/encryption.key` with label `kyguard:mfa_factors`; a code is accepted only when its counter is above the stored `last_counter`, by compare-and-swap. The base's retired columns (`totp_secret_enc`, `totp_enabled`, `totp_last_counter`, `recovery_codes_hash`) stay unused. There are no recovery codes.
- The SSO first factor never yields an active session directly: `IssuePendingSession` makes a restricted pending session (5 minutes, `stage = pending`, bound to issuer, `sid`, original `iat` and the token's MFA assertion) that `AuthenticateRequest` admits only for `pendingAllowed` routes (`ErrStepUpRequired` elsewhere). `ExchangePending` (store `ExchangeSession`, one transaction holding the user row) deletes it and issues a new active token for `SSOSessionTTL` (12 h) with the same binding, then re-checks the logout fences after commit (check-after-insert, like `CreateSession`). `CheckEnrollment` counts a first-factor code against the same limits.
- `ClientIP` is the one client-address helper: the rate limiter and session binding both use it. `X-Forwarded-For` is honoured only when the peer is in `KY_TRUSTED_PROXIES`, walking the chain from the right past trusted hops; `X-Real-IP` is ignored. Each entry may be a bare IP or `ip:port` (Azure App Service/Application Gateway append the port); anything else ends the walk and falls back to the peer.
- `RateLimitKey` reduces an IPv6 client to its /64 for rate limits; IPv4 is unchanged.

## Verification
- `go test -v ./internal/auth/...`

## Child DOX Index
None.
