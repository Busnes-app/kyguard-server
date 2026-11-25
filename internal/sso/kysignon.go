package sso

import (
	"context"
	"errors"

	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// KySignOnMFAACR is the acr KyIdentity asserts for an MFA login (spec §7.2), the KySignOn
// profile's whole MFA set.
const KySignOnMFAACR = "urn:kysignon:acr:mfa"

// KySignOnClient manages interactions with the central KySignOn identity provider.
type KySignOnClient struct {
	flow *oauthFlow
}

func NewKySignOnClient(cfg config.SSOConfig, _ store.Store) *KySignOnClient {
	return &KySignOnClient{
		flow: newOAuthFlow(cfg.KySignOnIssuer, cfg.KySignOnClientID, cfg.KySignOnSecret, []string{KySignOnMFAACR}),
	}
}

// BuildAuthURL generates the authorization code URL with PKCE for KySignOn.
func (k *KySignOnClient) BuildAuthURL(ctx context.Context, redirectURI, state, verifier, nonce string) (string, error) {
	return k.flow.authCodeURL(ctx, redirectURI, state, verifier, nonce)
}

// ExchangeCode exchanges the authorization code and verifier for identity claims.
func (k *KySignOnClient) ExchangeCode(ctx context.Context, code, verifier, redirectURI, expectedNonce string) (*IdentityClaims, error) {
	claims, err := k.flow.exchange(ctx, code, verifier, redirectURI, expectedNonce)
	if err != nil {
		return nil, err
	}
	claims.Provider = "kysignon"
	return claims, nil
}

// VerifyLogoutToken verifies a back-channel logout token signed by KySignOn for this client.
func (k *KySignOnClient) VerifyLogoutToken(ctx context.Context, raw string) (*LogoutClaims, error) {
	return k.flow.verifyLogout(ctx, raw)
}

// AdoptSCIMUser links a SCIM-provisioned account to the SSO login that matches it on
// (issuer, subject) (spec §7.2): a "scim" row whose issuer and externalId are this login's
// becomes a provider row and stays SCIM-managed, so back-channel logout and SCIM updates
// reach it and the IdP keeps managing it by id. Sign-in finds the row with GetUserBySSO and
// calls this when it is still "scim", so it never creates a second row for the same person.
// adopted reports whether this call made the link.
func AdoptSCIMUser(ctx context.Context, users store.UserStore, user *store.User, provider string) (adopted bool, err error) {
	if err := users.LinkSSOIdentity(ctx, user.ID, user.SSOSubject, "scim", provider); errors.Is(err, store.ErrConflict) {
		fresh, err := users.GetUserByID(ctx, user.ID) // a concurrent call linked it first
		if err == nil {
			*user = *fresh
		}
		return false, err
	} else if err != nil {
		return false, err
	}
	user.SSOProvider = provider
	return true, nil
}
