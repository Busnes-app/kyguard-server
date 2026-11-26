package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func sendJSON(srv *api.Server, session *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
	if session != nil {
		req.AddCookie(session)
		req.AddCookie(&http.Cookie{Name: auth.CSRFCookieName, Value: "test-csrf"})
		req.Header.Set(auth.HeaderCSRF, "test-csrf")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

func created(t *testing.T, w *httptest.ResponseRecorder, v any) {
	t.Helper()
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryWritesNeedAnAdmin(t *testing.T) {
	srv, st, _, _ := setupBrokerServer(t)
	admin := loginAs(t, srv, st, "admin1", "admin")
	user := loginAs(t, srv, st, "user1", "user")
	for _, c := range []struct{ method, path string }{
		{"GET", "/api/assets"}, {"POST", "/api/assets"}, {"POST", "/api/accounts"}, {"GET", "/api/accounts/x"},
		{"PATCH", "/api/accounts/x"}, {"PUT", "/api/accounts/x/target-descriptor"}, {"POST", "/api/attributes"},
		{"PATCH", "/api/attributes/x"}, {"DELETE", "/api/attributes/x"}, {"PUT", "/api/attributes/x/values/y"},
	} {
		if w := sendJSON(srv, nil, c.method, c.path, `{}`); w.Code != http.StatusUnauthorized {
			t.Errorf("anonymous %s %s: %d", c.method, c.path, w.Code)
		}
		if w := sendJSON(srv, user, c.method, c.path, `{}`); w.Code != http.StatusForbidden {
			t.Errorf("user %s %s: %d", c.method, c.path, w.Code)
		}
	}
	if w := sendJSON(srv, user, "GET", "/api/attributes", ""); w.Code != http.StatusOK {
		t.Errorf("user reading definitions: %d", w.Code)
	}

	for _, body := range []string{`{"name":"x"}]`, `{"name":"x"} {}`, `{"name":"x"}"y"`} {
		if w := sendJSON(srv, admin, "POST", "/api/assets", body); w.Code != http.StatusBadRequest {
			t.Fatalf("trailing data %s: %d", body, w.Code)
		}
	}
	var asset store.Asset
	created(t, sendJSON(srv, admin, "POST", "/api/assets", `{"name":"dc1.example.test"}`), &asset)
	var acct store.InventoryAccount
	created(t, sendJSON(srv, admin, "POST", "/api/accounts", `{"asset_id":"`+asset.ID+`","name":"svc-backup","account_kind":"vaulted","owner_user_id":"usr_user1"}`), &acct)
	if acct.OwnerUserID != "usr_user1" || acct.Status != "active" {
		t.Fatalf("account %+v", acct)
	}
	if w := sendJSON(srv, admin, "PATCH", "/api/accounts/"+acct.ID, `{"owner_user_id":"usr_ghost"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("unknown owner: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PATCH", "/api/accounts/"+acct.ID, `{"account_kind":"managed"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("kind changed after creation: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PATCH", "/api/accounts/"+acct.ID, `{"status":"decommissioned"}`); w.Code != http.StatusOK {
		t.Fatalf("decommission: %d %s", w.Code, w.Body)
	}
	if a, _ := st.Inventory().GetAccount(context.Background(), acct.ID); a.Status != "decommissioned" || a.OwnerUserID != "usr_user1" {
		t.Fatalf("after patch %+v", a)
	}
}

// The Control Plane rejects out-of-slice descriptors and ones for another account (§3.3).
func TestTargetDescriptorUpload(t *testing.T) {
	srv, st, _, d := setupBrokerServer(t)
	admin := loginAs(t, srv, st, "admin1", "admin")
	var asset store.Asset
	created(t, sendJSON(srv, admin, "POST", "/api/assets", `{"name":"web01"}`), &asset)
	var acct store.InventoryAccount
	created(t, sendJSON(srv, admin, "POST", "/api/accounts", `{"asset_id":"`+asset.ID+`","name":"root","account_kind":"managed"}`), &acct)
	key := pqcrypto.HexID(strings.Repeat("ab", 32))
	raw, digest := d.SSHTarget(t, pqcrypto.UUID(acct.ID), pqcrypto.UUID(asset.ID), "web01.example.test", 22, "root", key)
	path := "/api/accounts/" + acct.ID + "/target-descriptor"

	other, _ := d.SSHTarget(t, pqtest.UUID(), pqcrypto.UUID(asset.ID), "web01.example.test", 22, "root", key)
	if w := sendJSON(srv, admin, "PUT", path, string(other)); w.Code != http.StatusBadRequest {
		t.Fatalf("descriptor for another account: %d", w.Code)
	}
	var td map[string]any
	pqtest.Decode(t, raw, &td)
	td["connector_config"] = map[string]any{"script": "x"}
	if w := sendJSON(srv, admin, "PUT", path, string(pqtest.Canon(t, td))); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "slice") {
		t.Fatalf("out-of-slice descriptor: %d %s", w.Code, w.Body)
	}
	// A valid descriptor padded to the 64 KiB limit with more after it is too large, not
	// silently cut to the valid prefix.
	padded := string(raw) + strings.Repeat(" ", 64<<10-len(raw)) + "trailing"
	if w := sendJSON(srv, admin, "PUT", path, padded); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized descriptor: %d", w.Code)
	}
	var got map[string]string
	created(t, sendJSON(srv, admin, "PUT", path, string(raw)), &got)
	if got["digest"] != string(digest) {
		t.Fatalf("digest %s, want %s", got["digest"], digest)
	}
	stored, err := st.Inventory().Descriptors(context.Background(), acct.ID)
	if err != nil || len(stored) != 1 || !bytes.Equal(stored[0].Descriptor, raw) {
		t.Fatalf("stored %v %v", stored, err)
	}
	var view struct {
		Descriptors []map[string]any `json:"descriptors"`
	}
	created(t, sendJSON(srv, admin, "GET", "/api/accounts/"+acct.ID, ""), &view)
	if len(view.Descriptors) != 1 || view.Descriptors[0]["ssh_host_key_sha256"] != string(key) || view.Descriptors[0]["host"] != "web01.example.test" {
		t.Fatalf("view %+v", view)
	}
}

func TestAttributeDefinitionsAndValues(t *testing.T) {
	srv, st, _, _ := setupBrokerServer(t)
	admin := loginAs(t, srv, st, "admin1", "admin")
	ctx := context.Background()
	var asset store.Asset
	created(t, sendJSON(srv, admin, "POST", "/api/assets", `{"name":"db1"}`), &asset)
	var acct store.InventoryAccount
	created(t, sendJSON(srv, admin, "POST", "/api/accounts", `{"asset_id":"`+asset.ID+`","name":"sa","account_kind":"vaulted"}`), &acct)

	if w := sendJSON(srv, admin, "POST", "/api/attributes", `{"entity":"user","key":"department","label":"Dept","type":"string"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("admin defined a SCIM key: %d", w.Code)
	}
	var tier store.AttributeDefinition
	created(t, sendJSON(srv, admin, "POST", "/api/attributes", `{"entity":"account","key":"tier","label":"Tier","type":"enum","enum_values":["gold","silver"]}`), &tier)
	if w := sendJSON(srv, admin, "POST", "/api/attributes", `{"entity":"account","key":"tier","label":"Again","type":"string"}`); w.Code != http.StatusConflict {
		t.Fatalf("duplicate key: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PUT", "/api/attributes/"+tier.ID+"/values/"+acct.ID, `{"value":"bronze"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("value outside the enum: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PUT", "/api/attributes/"+tier.ID+"/values/"+acct.ID, `{"value":"gold"}`); w.Code != http.StatusOK {
		t.Fatalf("set value: %d %s", w.Code, w.Body)
	}
	for _, body := range []string{`{}`, `{"value":null}`} {
		if w := sendJSON(srv, admin, "PUT", "/api/attributes/"+tier.ID+"/values/"+acct.ID, body); w.Code != http.StatusBadRequest {
			t.Fatalf("%s cleared the value: %d", body, w.Code)
		}
	}
	if w := sendJSON(srv, admin, "PATCH", "/api/attributes/"+tier.ID, `{"label":"Tier","enum_values":["silver"]}`); w.Code != http.StatusConflict {
		t.Fatalf("removed a value in use: %d", w.Code)
	}
	var view struct {
		Attributes map[string]string `json:"attributes"`
	}
	created(t, sendJSON(srv, admin, "GET", "/api/accounts/"+acct.ID, ""), &view)
	if len(view.Attributes) != 1 || view.Attributes["tier"] != "gold" {
		t.Fatalf("account attributes %v", view.Attributes)
	}
	if w := sendJSON(srv, admin, "PATCH", "/api/attributes/"+tier.ID, `{"label":"Service tier"}`); w.Code != http.StatusOK {
		t.Fatalf("label-only update: %d %s", w.Code, w.Body)
	}

	// SCIM attributes are read-only to admins (§8.2).
	dept, err := st.Inventory().EnsureDefinition(ctx, &store.AttributeDefinition{ID: string(pqtest.UUID()), Entity: store.EntityUser, Key: "department", Label: "Department", Type: store.AttrString, Source: store.SourceSCIM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if w := sendJSON(srv, admin, "PUT", "/api/attributes/"+dept.ID+"/values/usr_admin1", `{"value":"Ops"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("admin wrote a SCIM value: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "DELETE", "/api/attributes/"+dept.ID, ""); w.Code != http.StatusBadRequest {
		t.Fatalf("admin deleted a SCIM definition: %d", w.Code)
	}
	vals, _ := st.Inventory().Values(ctx, store.EntityAccount)
	if vals[acct.ID]["tier"] != "gold" {
		t.Fatalf("values %v", vals)
	}
}
