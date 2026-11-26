package sso_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/ky-primitives/pqtls"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/sso"
	"github.com/coreos/go-oidc/v3/oidc"
)

// PQC W0: outbound OIDC HTTPS negotiates the hybrid X25519MLKEM768 group both normally
// and under GODEBUG=fips140=on.
func TestOIDCOutboundTLSNegotiatesHybrid(t *testing.T) {
	var issuer string
	var gotTLS tls.ConnectionState
	idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			gotTLS = *r.TLS
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": issuer + "/authorize",
			"token_endpoint":         issuer + "/token",
			"jwks_uri":               issuer + "/keys",
		})
	}))
	defer idp.Close()
	issuer = idp.URL

	ctx := oidc.ClientContext(context.Background(), idp.Client())
	client := sso.NewKySignOnClient(config.SSOConfig{KySignOnIssuer: issuer, KySignOnClientID: "client"}, nil)
	if _, err := client.BuildAuthURL(ctx, "https://app.example/callback", "state", "verifier", "nonce"); err != nil {
		t.Fatalf("BuildAuthURL: %v", err)
	}
	pqtls.RequireHybrid(t, gotTLS)
}
