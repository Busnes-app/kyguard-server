package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Spec §3.3, §10: an admin drafts the next policy, Custodians sign it, and the Control
// Plane accepts it only at quorum. The draft never changes under a signature.
func TestPolicyDraftSigning(t *testing.T) {
	srv, st, _, d := setupBrokerServer(t)
	ctx := context.Background()
	admin := loginAs(t, srv, st, "admin1", "admin")
	user := loginAs(t, srv, st, "user1", "user")

	pool := pqtest.UUID()
	sig, _ := pqcrypto.GenerateSigningKey()
	enc, _ := recoverykey.Generate()
	b := &pqtest.Broker{ID: pqtest.UUID(), Sig: sig, Enc: enc, CertSHA256: pqcrypto.HexID(strings.Repeat("cd", 32))}
	if w := postJSON(srv, admin, "/api/manifests", d.Pool(t, pool, 1, []pqcrypto.BrokerMember{b.Member(pqcrypto.StatusActive)}, nil)); w.Code != http.StatusCreated {
		t.Fatal(w.Code)
	}
	alice := pqtest.NewPrincipal(t)
	if w := postJSON(srv, admin, "/api/manifests", d.Enrollment(t, alice, 1)); w.Code != http.StatusCreated {
		t.Fatal(w.Code)
	}
	if err := st.Guard().CreatePool(ctx, &store.BrokerPool{ID: string(pool), Name: "p", CreatedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatal(err)
	}
	var asset store.Asset
	created(t, sendJSON(srv, admin, "POST", "/api/assets", `{"name":"web01"}`), &asset)
	var acct store.InventoryAccount
	created(t, sendJSON(srv, admin, "POST", "/api/accounts", `{"asset_id":"`+asset.ID+`","name":"root","account_kind":"managed","pool_id":"`+string(pool)+`"}`), &acct)
	raw, dg := d.SSHTarget(t, pqcrypto.UUID(acct.ID), pqcrypto.UUID(asset.ID), "web01", 22, "root", pqcrypto.HexID(strings.Repeat("ab", 32)))
	path := "/api/accounts/" + acct.ID + "/policy-draft"
	form := func(mode, target string, users ...string) string {
		ids, _ := json.Marshal(users)
		return `{"checkout_mode":"` + mode + `","target_descriptor_digest":"` + target + `","enroller_principal_ids":` + string(ids) +
			`,"allowed_user_principal_ids":` + string(ids) + `,"max_checkout_ttl_seconds":3600,` +
			`"rotation_schedule":{"anchor_utc":"2026-11-01T00:00:00Z","interval_seconds":86400}}`
	}

	if w := sendJSON(srv, admin, "PUT", path, form("ephemeral", string(dg), string(alice.ID))); w.Code != http.StatusBadRequest {
		t.Fatalf("draft pinning a descriptor never uploaded: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PUT", "/api/accounts/"+acct.ID+"/target-descriptor", string(raw)); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}
	if w := sendJSON(srv, user, "PUT", path, form("ephemeral", string(dg), string(alice.ID))); w.Code != http.StatusForbidden {
		t.Fatalf("user drafted a policy: %d", w.Code)
	}
	if w := sendJSON(srv, admin, "PUT", path, form("ephemeral", string(dg), string(pqtest.UUID()))); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "unknown_principal") {
		t.Fatalf("unenrolled principal: %d %s", w.Code, w.Body)
	}
	if w := sendJSON(srv, admin, "PUT", path, form("proxy_only", string(dg), string(alice.ID))); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("proxy_only draft: %d %s", w.Code, w.Body)
	}
	var draft store.PolicyDraft
	created(t, sendJSON(srv, admin, "PUT", path, form("ephemeral", string(dg), string(alice.ID))), &draft)
	if draft.Epoch != 1 || len(draft.Digest) != 64 {
		t.Fatalf("draft %+v", draft)
	}

	// kyguard-cli fetches the object, shows the pinned target and signs.
	var got struct {
		Object json.RawMessage `json:"object"`
		Target json.RawMessage `json:"target"`
	}
	created(t, sendJSON(srv, user, "GET", "/api/policy-drafts/"+draft.ID, ""), &got)
	if string(got.Target) != string(raw) {
		t.Fatalf("target %s", got.Target)
	}
	sign := func(obj []byte, k *pqcrypto.SigningKey) ([]byte, *pqcrypto.PolicyManifest) {
		t.Helper()
		var pm pqcrypto.PolicyManifest
		pqtest.Decode(t, obj, &pm)
		if err := pqcrypto.Sign(&pm, pqcrypto.RoleCustodian, k); err != nil {
			t.Fatal(err)
		}
		return pqtest.Canon(t, &pm), &pm
	}
	sigPath := "/api/policy-drafts/" + draft.ID + "/signatures"
	one, _ := sign(got.Object, d.Custodians[0])
	var res map[string]any
	created(t, sendJSON(srv, user, "POST", sigPath, string(one)), &res)
	if res["accepted"] != false {
		t.Fatalf("accepted below quorum: %v", res)
	}

	// A changed body is another object; dropping a collected signature is refused.
	var changed pqcrypto.PolicyManifest
	pqtest.Decode(t, one, &changed)
	changed.MaxCheckoutTTLSeconds = 7200
	if w := sendJSON(srv, user, "POST", sigPath, string(pqtest.Canon(t, &changed))); w.Code != http.StatusConflict {
		t.Fatalf("changed body: %d", w.Code)
	}
	other, _ := sign(got.Object, d.Custodians[1])
	if w := sendJSON(srv, user, "POST", sigPath, string(other)); w.Code != http.StatusConflict {
		t.Fatalf("dropped signature: %d %s", w.Code, w.Body)
	}
	if p := currentPolicy(t, srv, st, acct.ID); p != nil {
		t.Fatal("policy accepted before quorum")
	}

	both, _ := sign(one, d.Custodians[1])
	// A fully signed draft whose admission was interrupted is ready, not stale.
	if err := st.Drafts().SetDraftObject(ctx, draft.ID, one, both, nil); err != nil {
		t.Fatal(err)
	}
	var ready []map[string]any
	created(t, sendJSON(srv, user, "GET", "/api/policy-drafts", ""), &ready)
	if len(ready) != 1 || ready[0]["status"] != "ready" {
		t.Fatalf("interrupted draft %v", ready)
	}
	created(t, sendJSON(srv, user, "POST", sigPath, string(both)), &res)
	if res["accepted"] != true {
		t.Fatalf("not accepted at quorum: %v", res)
	}
	if p := currentPolicy(t, srv, st, acct.ID); p == nil || p.Digest != draft.Digest {
		t.Fatalf("accepted policy %+v", p)
	}
	if _, err := st.Drafts().GetDraft(ctx, draft.ID); err == nil {
		t.Fatal("draft kept after acceptance")
	}

	// A draft made for epoch 2 goes stale when another epoch-2 policy is accepted first.
	created(t, sendJSON(srv, admin, "PUT", path, form("standing", string(dg), string(alice.ID))), &draft)
	if draft.Epoch != 2 {
		t.Fatalf("next epoch %d", draft.Epoch)
	}
	pm := d.ManagedPolicy(pqcrypto.UUID(acct.ID), pool, 2, dg)
	if w := postJSON(srv, admin, "/api/manifests", d.Signed(t, pm)); w.Code != http.StatusCreated {
		t.Fatal(w.Code)
	}
	var list []map[string]any
	created(t, sendJSON(srv, user, "GET", "/api/policy-drafts", ""), &list)
	if len(list) != 1 || list[0]["status"] != "stale" || list[0]["code"] == "" {
		t.Fatalf("drafts %v", list)
	}
}

type acceptedPolicy struct{ Digest string }

func currentPolicy(t *testing.T, _ any, st store.Store, account string) *acceptedPolicy {
	t.Helper()
	ms, err := st.Guard().Manifests(context.Background(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var out *acceptedPolicy
	for _, m := range ms {
		if m.Type == pqcrypto.TypePolicy && m.ScopeID == account {
			out = &acceptedPolicy{Digest: m.Digest}
		}
	}
	return out
}
