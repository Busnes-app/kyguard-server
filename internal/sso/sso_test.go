package sso_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/sso"
	"github.com/coreos/go-oidc/v3/oidc"
)

func TestOAuthAuthorizationURLUsesDiscoveryAndPKCE(t *testing.T) {
	var issuer string
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
			"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
		})
	}))
	defer idp.Close()
	issuer = idp.URL

	client := sso.NewKySignOnClient(config.SSOConfig{KySignOnIssuer: issuer, KySignOnClientID: "client"}, nil)
	ctx := oidc.ClientContext(context.Background(), idp.Client())
	authURL, err := client.BuildAuthURL(ctx, "https://app.example/callback", "state", "verifier", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(authURL)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	if parsed.Path != "/authorize" || query.Get("state") != "state" || query.Get("nonce") != "nonce" || query.Get("code_challenge_method") != "S256" || query.Get("code_challenge") == "" {
		t.Fatalf("unexpected authorization URL: %s", authURL)
	}
}

// Acceptance 6 (rule): amr "otp", "hwk" or "swk" alone is not MFA; "mfa" is, and so is an acr
// in the issuer profile's MFA set.
func TestMFAAssertionRule(t *testing.T) {
	set := []string{sso.KySignOnMFAACR}
	for _, c := range []struct {
		amr  []string
		acr  string
		want bool
	}{
		{[]string{"otp"}, "", false},
		{[]string{"hwk", "swk", "pwd"}, "", false},
		{[]string{"pwd", "mfa"}, "", true},
		{nil, sso.KySignOnMFAACR, true},
		{[]string{"otp"}, "urn:other:acr", false},
	} {
		if got := sso.MFAAsserted(c.amr, c.acr, set); got != c.want {
			t.Errorf("amr %v acr %q: %v, want %v", c.amr, c.acr, got, c.want)
		}
	}
	if sso.MFAAsserted([]string{"otp"}, "", nil) {
		t.Error("an empty MFA set made otp count")
	}
}
