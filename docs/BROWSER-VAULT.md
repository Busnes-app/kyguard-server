# Browser vault and KyIdentity keyring

[Overview](../README.md) · [API reference](INTERFACES.md) · [Design](SPEC.md#101-browser-vault)

KyGuard's SaaS vault uses the browser as the user client. Generate and unlock
KyGuard signing and encryption keys locally. The Control Plane holds a sealed
bundle and a public enrollment request. KyIdentity's suite keyring can unlock
that bundle with its KyGuard app subkey. A separate vault passphrase is also
available when setting up a key. SSO and KyGuard's authenticator code remain
required regardless of the selection.

## Deploy the trusted browser client

1. Run `make build-browser-vault` from the release source. It builds the usual
   web UI, then adds the Go WASM client and its matching Go runtime to
   `web/vault-dist`. Deploy that directory from a trusted release pipeline to
   a separate HTTPS edge on a dedicated hostname for the browser origin. The
   Control Plane must have no write access to those assets, the edge configuration or the browser's
   trusted bootstrap configuration.
2. Use [the Caddy example](../deploy/browser-vault/Caddyfile) with
   `KY_VAULT_ORIGIN=https://guard.example.com` and `KY_CONTROL_PLANE` pointing
   at the private API listener. Copy the released static directory to
   `/srv/kyguard-vault`. Keep the API listener private. The edge serves the
   shell, runtime, worker and WASM itself. Only API, SCIM and health requests
   go to the Control Plane. Keep the API response sandbox and header filtering
   if using another reverse proxy. Serve `.wasm` as `application/wasm`.
3. Set `KY_APP_URL` to the same public HTTPS origin and `KY_BROWSER_VAULT=true`
   on KyGuard. Set `KY_TRUSTED_PROXIES` to the edge's address for client-IP limits.
   On PostgreSQL follow [replica configuration changes](REPLICAS.md) before
   enabling the feature on every replica.
4. On the independent edge, place `.well-known/kyguard-vault.json` inside
   `/srv/kyguard-vault`. Set `fingerprint` to the bootstrap bundle fingerprint
   checked with Custodians through an independent channel. For a passphrase-only
   deployment the file needs only `fingerprint`. With KyIdentity it also has
   the following fields.

   ```json
   {
     "fingerprint": "<verified 64 lowercase hex characters>",
     "keyring": {
       "issuer": "https://identity.example.com",
       "client_id": "kyguard",
       "org_id": "<KyIdentity's opaque organization ID>"
     }
   }
   ```

## Enable the KyIdentity handoff

Use a KyIdentity release that supports the X-Wing OIDC handoff. Add
`https://guard.example.com/vault/keyring-callback` as an exact redirect URI for
the usual KyGuard KySignOn OAuth client. Retain the existing SSO callback.
Set `KY_KYSIGNON_KEYRING_ORG_ID` to that same opaque organization ID, even on a
single-tenant KyIdentity installation. The browser authenticates the organization
as part of the handoff. The origin, client ID and issuer must match the trusted
file and the existing KySignOn configuration.

Choose **Sign in with KyIdentity keyring** and complete KyIdentity's unlock or
setup if prompted. After KyGuard step-up, open **Vault**. Choose **Use KyIdentity
keyring** to create a KyGuard key protected by the app subkey. KyIdentity's
administrators, staff, export-only sessions and workstation sessions skip the
handoff. A user with no available app subkey can create a passphrase-protected key.

KyIdentity keeps the app-subkey envelope and handles its trusted browsers,
passkeys and Emergency Kit. KyGuard receives no suite root key, app subkey or
vault passphrase. The browser opens the handoff locally, keeps the app subkey in
memory, and clears the callback fragment before exchanging the code. Reloading
the page or choosing **Lock vault** clears the app subkey. Sign in with the
keyring again to unlock. Coordinate any KyIdentity **app subkey rotation**
before revoking the old version. The current browser
vault keys use one wrapping method fixed at enrollment and require the original
app subkey version or passphrase. Changing the login password or TOTP does not
recover that bundle.

## Enroll and check out

1. In **Vault**, create and unlock the browser key. Download its self-signed
   enrollment request. Check the issuer, subject, principal and public key fingerprints
   with a Custodian over an independent channel. A Custodian signs using their
   offline key. Upload the completed, quorum-signed file and unlock the key.
2. Choose an authorized managed account and verify the displayed target. Enter a
   password in **Enroll credential** to seal it for the broker in the browser.
   When approval is required, exchange the signed request with the listed
   approvers and upload the approved file before the reservation expires.
   The broker verifies the credential at the target.
3. For an ephemeral policy, prepare a checkout. When the policy requires
   approval, send the request file to a listed approver. Each approver reviews
   and signs the file in **Vault**. Load the final approved copy, submit the
   checkout, and refresh to answer the broker challenge and open the delivery.
4. Check in and refresh to complete the check-in challenge. If the browser loses
   the checkout state, the broker starts cleanup at expiry. The key and
   plaintext credential stay in browser memory. Backup copies contain only
   encrypted bundles.

Custodian keys stay offline and separate from user keyring keys. Compromise of
the trusted edge or KyIdentity browser code can expose the material those
origins handle. Serving the vault assets from the Control Plane puts its
runtime in the browser's trust boundary.
