package scim_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/scim"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

// Spec §8.2: title (core) and department and manager.value (Enterprise User) land in
// SCIM-sourced user attributes, follow PATCH and PUT, and go with the user.
func TestEnterpriseUserAttributes(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, testdb.Config(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	const token = "scim-secret-bearer-token"
	srv := scim.NewServer(st, config.SCIMConfig{Enabled: true, BearerToken: token}, "http://localhost:8080")
	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)
	h := srv.AuthMiddleware(mux)
	do := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/scim+json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w
	}
	attrs := func(id string) map[string]string {
		t.Helper()
		vals, err := st.Inventory().Values(ctx, store.EntityUser)
		if err != nil {
			t.Fatal(err)
		}
		return vals[id]
	}

	// A create whose attributes cannot be written leaves no user behind, so a retry works.
	g := &store.User{ID: "usr_gil", Username: "gil", Role: "user", Status: "active", SSOProvider: "scim", SCIMManaged: true}
	if err := st.Users().CreateUser(ctx, g); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Inventory().EnsureDefinition(ctx, &store.AttributeDefinition{ID: "blocker", Entity: store.EntityUser, Key: "title", Label: "T", Type: store.AttrString, Source: store.SourceAdmin}, nil); err != nil {
		t.Fatal(err)
	}
	if w := do("POST", "/scim/v2/Users", map[string]any{"schemas": []string{scim.SchemaUser, scim.SchemaEnterpriseUser}, "userName": "fay", "active": true, "title": "CTO",
		scim.SchemaEnterpriseUser: map[string]any{"department": "Ops", "manager": map[string]any{"value": "mgr-1"}}}); w.Code < 400 {
		t.Fatalf("create with a failing attribute write: %d", w.Code)
	}
	if _, err := st.Users().GetUserByUsername(ctx, "fay"); err == nil {
		t.Fatal("half-created user left behind")
	}
	// Nor does it claim the other keys: an admin can still define department.
	if defs, err := st.Inventory().Definitions(ctx, store.EntityUser); err != nil || len(defs) != 1 {
		t.Fatalf("a refused create left definitions behind: %d %v", len(defs), err)
	}
	// The same holds for a PATCH: its profile change is not written either.
	{
		ops := map[string]any{"schemas": []string{scim.SchemaPatchOp}, "Operations": []map[string]any{{"op": "replace", "value": map[string]any{"userName": "gil2", "title": "CTO"}}}}
		if w := do("PATCH", "/scim/v2/Users/"+g.ID, ops); w.Code < 400 {
			t.Fatalf("patch with a failing attribute write: %d", w.Code)
		}
		if u, err := st.Users().GetUserByID(ctx, g.ID); err != nil || u.Username != "gil" {
			t.Fatalf("patch half-applied: %+v %v", u, err)
		}
	}
	if err := st.Inventory().DeleteDefinition(ctx, "blocker", nil); err != nil {
		t.Fatal(err)
	}
	w := do("POST", "/scim/v2/Users", map[string]any{
		"schemas":  []string{scim.SchemaUser, scim.SchemaEnterpriseUser},
		"userName": "erin", "active": true, "title": "DBA", "externalId": "erin-1",
		scim.SchemaEnterpriseUser: map[string]any{"department": "Ops", "manager": map[string]any{"value": "mgr-7"}},
	})
	if w.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", w.Code, w.Body)
	}
	var res struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &res)
	if a := attrs(res.ID); a["title"] != "DBA" || a["department"] != "Ops" || a["manager"] != "mgr-7" {
		t.Fatalf("after create %v", a)
	}
	defs, _ := st.Inventory().Definitions(ctx, store.EntityUser)
	for _, d := range defs {
		if d.Source != store.SourceSCIM {
			t.Fatalf("definition %s has source %s", d.Key, d.Source)
		}
	}

	patch := func(ops ...map[string]any) {
		t.Helper()
		if w := do("PATCH", "/scim/v2/Users/"+res.ID, map[string]any{"schemas": []string{scim.SchemaPatchOp}, "Operations": ops}); w.Code != http.StatusOK {
			t.Fatalf("patch: %d %s", w.Code, w.Body)
		}
	}
	patch(map[string]any{"op": "replace", "path": scim.SchemaEnterpriseUser + ":department", "value": "Sales"})
	patch(map[string]any{"op": "remove", "path": scim.SchemaEnterpriseUser + ":manager"})
	patch(map[string]any{"op": "replace", "value": map[string]any{"title": "Lead DBA"}})
	if a := attrs(res.ID); a["department"] != "Sales" || a["manager"] != "" || a["title"] != "Lead DBA" {
		t.Fatalf("after patch %v", a)
	}
	patch(map[string]any{"op": "add", "path": scim.SchemaEnterpriseUser + ":manager.value", "value": "mgr-9"})
	if a := attrs(res.ID); a["manager"] != "mgr-9" {
		t.Fatalf("manager.value %v", a)
	}
	// manager.displayName and $ref are not stored: changing them leaves the manager alone.
	patch(map[string]any{"op": "replace", "path": scim.SchemaEnterpriseUser + ":manager.displayName", "value": "Mona"},
		map[string]any{"op": "remove", "path": scim.SchemaEnterpriseUser + ":manager.$ref"},
		map[string]any{"op": "replace", "value": map[string]any{scim.SchemaEnterpriseUser: map[string]any{"manager": map[string]any{"displayName": "Mona"}}}})
	if a := attrs(res.ID); a["manager"] != "mgr-9" {
		t.Fatalf("manager sub-attribute changed the manager: %v", a)
	}

	// The extension object as a PATCH path is refused by the SCIM library (invalidPath), so
	// it can never succeed without syncing.
	if w := do("PATCH", "/scim/v2/Users/"+res.ID, map[string]any{"schemas": []string{scim.SchemaPatchOp}, "Operations": []map[string]any{
		{"op": "add", "path": scim.SchemaEnterpriseUser, "value": map[string]any{"department": "Legal"}}}}); w.Code != http.StatusBadRequest {
		t.Fatalf("extension path: %d %s", w.Code, w.Body)
	}

	// title with the core schema URI is the same attribute.
	patch(map[string]any{"op": "replace", "path": scim.SchemaUser + ":title", "value": "Principal DBA"})
	if a := attrs(res.ID); a["title"] != "Principal DBA" {
		t.Fatalf("schema-qualified title %v", a)
	}

	// A PUT is the whole resource: what it omits is cleared.
	if w := do("PUT", "/scim/v2/Users/"+res.ID, map[string]any{"schemas": []string{scim.SchemaUser}, "userName": "erin", "active": true, "externalId": "erin-1",
		"title": "DBA"}); w.Code != http.StatusOK {
		t.Fatalf("put: %d %s", w.Code, w.Body)
	}
	if a := attrs(res.ID); len(a) != 1 || a["title"] != "DBA" {
		t.Fatalf("after put %v", a)
	}

	// Deleting a user who owns an account leaves the account unowned.
	if err := st.Inventory().CreateAsset(ctx, &store.Asset{ID: "as", Name: "h"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := st.Inventory().CreateAccount(ctx, &store.InventoryAccount{Account: store.Account{ID: "ac", AssetID: "as", Name: "svc", AccountKind: "vaulted"}, OwnerUserID: res.ID}, nil); err != nil {
		t.Fatal(err)
	}
	if w := do("DELETE", "/scim/v2/Users/"+res.ID, nil); w.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	if a, _ := st.Inventory().GetAccount(ctx, "ac"); a.OwnerUserID != "" {
		t.Fatalf("account still owned by %s", a.OwnerUserID)
	}
	if a := attrs(res.ID); len(a) != 0 {
		t.Fatalf("attributes outlived the user: %v", a)
	}

}
