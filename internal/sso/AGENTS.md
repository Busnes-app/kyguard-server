# SSO

## Purpose
Provides Single Sign-On federation for KySignOn and one generic OpenID Connect profile (spec §7.2). SAML is removed: it cannot carry the `max_age` and `auth_time` guarantees step-up needs.

## Ownership
Owns the application adapters around OAuth/OIDC login and verified back-channel logout. KyIdentity directory synchronization belongs to the SCIM connector, not a webhook.

## Local Contracts
- The KyIdentity keyring path verifies the OIDC token through the usual KySignOn client.
  Its optional `org_id` claim is compared with the configured keyring organization.
- PKCE with `S256` is enforced on all OAuth/OIDC authorization requests.
- ID tokens require provider signature, issuer, audience, expiry, and one-time nonce verification before claims are trusted.
- OAuth discovery, authorization URLs, PKCE parameters, code exchange, key
  caching/rotation and token verification stay in `oauth2`/`coreos/go-oidc`.
  `jwks_strength.go` bounds the verifier's private JWKS client, refuses redirects
  and rejects RSA members below 2048 actual modulus bits before caching. The
  provider/verifier pair is initialized once under the discovery mutex.
  Match the verifier's envelope parsing and go-jose's case-sensitive JWK member
  parsing; case variants must never substitute another modulus for this check.
- Discovery and token exchange use a client with a 10 s timeout in every mode
  (`strongOIDCContext`), because discovery holds the provider mutex.
- When `fips140.Enabled()`, issuer/authorization/token/JWKS endpoints require
  HTTPS without URL credentials; discovery/token redirects are refused. Preserve
  caller TLS trust roots and ordinary verification. This mode is process-wide.
- No SAML code, route or setting: `/saml/*` answers 404 (`TestSAMLRoutesAreGone`).
- `VerifyLogoutToken` (`backchannel.go`) reuses the ID-token verifier, then requires
  `iat`, `sub` or `sid`, the back-channel logout event as a JSON object and no `nonce`;
  a present `typ` must be `logout+jwt`. Every failure is `ErrInvalidLogoutToken`.
  `IdentityClaims.SessionID` and `IssuedAt` carry the ID token `sid` and `iat` so sessions can be ended by them.
- `IdentityClaims.Roles` is the per-app `roles` claim (nil when absent; a non-array is an invalid token). `LocalRole` maps it: `admin` in `roles` is admin, anything else (no `roles` included) is user. The IdP-wide `role` is never used (spec §7.2), and the callback writes the result at every sign-in.
- Identity is `(Issuer, Subject)`: `IdentityClaims.Issuer` is the verified token's `iss`, `LogoutClaims.Issuer` the logout token's. Store lookups and both logout fences take the issuer.
- Step-up layer 1: `authCodeURL` sends `max_age=0` and the profile's MFA acr set as `acr_values`; `claimsFromIDToken` parses `auth_time`, `amr`, `acr`; `CheckFresh` refuses `auth_time` missing, older than `MaxAuthAge` (120 s) or in the future; `MFAAsserted` is the MFA rule (`amr` has `mfa`, or `acr` in the set; `otp`/`hwk`/`swk` alone never). KySignOn's set is `KySignOnMFAACR`.
- `AdoptSCIMUser` links the SCIM row the callback found by `(issuer, subject)` to the
  signing-in provider, retaining its SCIM management and id.

## Verification
- `go test -v ./internal/sso/...` (`TestVerifyLogoutToken` holds one rejection case per logout-token rule)
- Repeat with `GODEBUG=fips140=on`: RSA-1024/2047 refusal, strong token/cache/nonce
  behavior, bounded/malformed/redirected JWKS, HTTPS
  metadata policy and refusal of a trusted RSA-1024 TLS peer.
- `TestOIDCJWKMemberParsingMatchesVerifier` uses real RSA signatures in both
  adapters to check case variants, member order, and strong-key acceptance.

## Child DOX Index
None.
