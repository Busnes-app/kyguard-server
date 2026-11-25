package scim_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/scim"
)

// With no issuer configured SCIM refuses every externalId, so no write it accepts leaves a
// subject without an issuer (which the next start refuses). Once one is set, an account
// created without it takes it with its first subject.
func TestSCIMNeverStoresASubjectWithoutAnIssuer(t *testing.T) {
	st, _ := scopedSCIM(t)
	ctx := context.Background()
	bare := scimFor(st, "")
	if w := bare("POST", "/scim/v2/Users", map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "ann", "externalId": "sub-ann"}); w.Code != http.StatusBadRequest {
		t.Fatalf("create with externalId, no issuer: %d %s", w.Code, w.Body)
	}
	if w := bare("POST", "/scim/v2/Users", map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "bob"}); w.Code != http.StatusCreated {
		t.Fatalf("create without externalId: %d %s", w.Code, w.Body)
	}
	bob, err := st.Users().GetUserByUsername(ctx, "bob")
	if err != nil {
		t.Fatal(err)
	}
	patch := map[string]any{"schemas": patchSchema, "Operations": []any{map[string]any{"op": "replace", "path": "externalId", "value": "sub-bob"}}}
	if w := bare("PATCH", "/scim/v2/Users/"+bob.ID, patch); w.Code != http.StatusBadRequest {
		t.Fatalf("PATCH externalId, no issuer: %d %s", w.Code, w.Body)
	}
	if w := bare("PUT", "/scim/v2/Users/"+bob.ID, map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "bob", "externalId": "sub-bob"}); w.Code != http.StatusBadRequest {
		t.Fatalf("PUT externalId, no issuer: %d %s", w.Code, w.Body)
	}
	if n, err := st.Users().CountUnissuedIdentities(ctx); err != nil || n != 0 {
		t.Fatalf("%d unissued identities (%v): the next start would refuse", n, err)
	}
	if w := scimFor(st, testIssuer)("PATCH", "/scim/v2/Users/"+bob.ID, patch); w.Code != http.StatusOK {
		t.Fatalf("PATCH externalId once an issuer is set: %d %s", w.Code, w.Body)
	}
	if got, err := st.Users().GetUserBySSO(ctx, testIssuer, "sub-bob"); err != nil || got.ID != bob.ID {
		t.Fatalf("subject not stored under the issuer: %v %v", got, err)
	}
}
