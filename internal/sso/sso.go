package sso

import (
	"errors"
	"slices"
	"time"
)

var (
	ErrInvalidState       = errors.New("invalid or expired SSO state")
	ErrInvalidIDToken     = errors.New("invalid ID token")
	ErrProviderDisabled   = errors.New("SSO provider is not enabled")
	ErrInvalidLogoutToken = errors.New("invalid logout token")
)

// IdentityClaims holds the unified identity extracted from any SSO provider.
type IdentityClaims struct {
	Subject           string `json:"sub"`
	Organization      string `json:"-"`
	HasOrganization   bool   `json:"-"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Role              string `json:"role,omitempty"`
	// Roles is KyIdentity's per-app `roles` claim; nil when the ID token has none.
	Roles    []string `json:"roles,omitempty"`
	Provider string   `json:"provider"` // "kysignon", "oidc"
	// SessionID is the provider's ID token `sid`; back-channel logout names the login by it.
	SessionID string `json:"sid,omitempty"`
	// IssuedAt is the ID token's iat: when the provider vouched for this login.
	IssuedAt time.Time `json:"-"`
	// Issuer is the verified ID token's iss; with Subject it is the account's identity.
	Issuer string `json:"-"`
	// AuthTime is the ID token's auth_time; zero when absent.
	AuthTime time.Time `json:"-"`
	AMR      []string  `json:"-"`
	ACR      string    `json:"-"`
	// MFA reports whether the token asserted multi-factor authentication under the issuer
	// profile's rule (MFAAsserted).
	MFA bool `json:"-"`
}

// MaxAuthAge is how old an ID token's auth_time may be at the callback (spec §7.2): requests
// send max_age=0, so the IdP authenticated the user just now.
const MaxAuthAge = 120 * time.Second

// ErrStaleAuth refuses an ID token whose auth_time is missing, older than MaxAuthAge or in
// the future.
var ErrStaleAuth = errors.New("ID token auth_time is missing or not fresh")

// CheckFresh enforces the freshness half of step-up layer 1.
func (c *IdentityClaims) CheckFresh(now time.Time) error {
	if c.AuthTime.IsZero() || now.Sub(c.AuthTime) > MaxAuthAge || c.AuthTime.After(now.Add(time.Minute)) {
		return ErrStaleAuth
	}
	return nil
}

// MFAAsserted is the MFA assertion rule (spec §7.2): amr contains "mfa", or acr is in the
// issuer profile's MFA set. otp, hwk or swk alone is not enough.
func MFAAsserted(amr []string, acr string, mfaACRs []string) bool {
	return slices.Contains(amr, "mfa") || (acr != "" && slices.Contains(mfaACRs, acr))
}

// LocalRole maps the per-app `roles` claim to this app's role: "admin" in it means admin,
// anything else, including no `roles` claim, means user. The IdP-wide `role` is never used
// (spec §7.2), and the result replaces the stored role at every sign-in.
func (c *IdentityClaims) LocalRole() string {
	if slices.Contains(c.Roles, "admin") {
		return "admin"
	}
	return "user"
}

// SSOState represents ephemeral state held during OAuth/OIDC authorization flow.
type SSOState struct {
	State        string    `json:"state"`
	Verifier     string    `json:"verifier"`
	Provider     string    `json:"provider"`
	RedirectBack string    `json:"redirect_back"`
	CreatedAt    time.Time `json:"created_at"`
}
