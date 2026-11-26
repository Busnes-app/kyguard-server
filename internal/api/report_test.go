package api_test

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/auth"
	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/config"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
	"github.com/Busnes-app/kyguard-server/internal/testdb"
)

type card struct {
	Totals struct {
		Active, Decommissioned int
		Classes                map[string]int
		Percent                map[string]int
		Health                 map[string]int
	} `json:"totals"`
	Rows []struct {
		AccountID string `json:"account_id"`
		Class     string `json:"class"`
		Health    string `json:"health"`
	} `json:"rows"`
}

func getCard(t *testing.T, srv *api.Server, c *http.Cookie, query string) (*httptest.ResponseRecorder, card) {
	t.Helper()
	w := sendJSON(srv, c, "GET", "/api/reports/scorecard"+query, "")
	var out card
	if w.Code == http.StatusOK && strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
	}
	return w, out
}

// Acceptance 12 (§8.1–§8.3): classes sum to the active count; the dashboard, the JSON
// export and the CSV export agree for one filter; a department filter from SCIM reaches
// accounts through their owner; a non-admin sees only what they own or are listed on.
func TestScorecard(t *testing.T) {
	dir := t.TempDir()
	if _, err := brokerproto.CreateCA(dir); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KY_DATA_DIR", dir)
	t.Setenv("KY_KYSIGNON_ISSUER", "https://idp.example.test")
	cfg, err := config.LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	cfg.Database = testdb.Config(t)
	cfg.Database.DataDir = dir
	cfg.Captcha.Provider = "none"
	st, err := store.Open(context.Background(), cfg.Database)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	d := pqtest.New(t)
	ctx := context.Background()
	if err := st.Guard().ImportBundle(ctx, &store.BootstrapBundle{DeploymentID: string(d.ID), Fingerprint: string(d.Fingerprint), Bundle: d.Bundle}, "host"); err != nil {
		t.Fatal(err)
	}
	srv := api.NewServer(cfg, st)
	admin := loginAs(t, srv, st, "admin1", "admin")
	owner := loginAs(t, srv, st, "owner1", "user")
	submit := func(raw []byte) {
		t.Helper()
		if w := postJSON(srv, admin, "/api/manifests", raw); w.Code != http.StatusCreated {
			t.Fatalf("manifest: %d %s", w.Code, w.Body)
		}
	}

	// carol signs in through KySignOn and is enrolled as a principal with the same identity.
	carolP := pqtest.NewPrincipal(t)
	carol := &store.User{ID: "usr_carol", Username: "carol", Role: "user", Status: "active", SSOProvider: "kysignon", SSOSubject: "sub-" + string(carolP.ID), SSOIssuer: "https://idp.example.test"}
	if err := st.Users().CreateUser(ctx, carol); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if _, _, err := auth.NewSessionManager(st, cfg.Security).IssueSession(ctx, rec, httptest.NewRequest("GET", "/", nil), carol); err != nil {
		t.Fatal(err)
	}
	carolCookie := rec.Result().Cookies()[0]
	submit(d.Enrollment(t, carolP, 1))

	pool := pqtest.UUID()
	sig, _ := pqcrypto.GenerateSigningKey()
	enc, _ := recoverykey.Generate()
	b := &pqtest.Broker{ID: pqtest.UUID(), Sig: sig, Enc: enc, CertSHA256: pqcrypto.HexID(strings.Repeat("cd", 32))}
	submit(d.Pool(t, pool, 1, []pqcrypto.BrokerMember{b.Member(pqcrypto.StatusActive)}, nil))
	if err := st.Guard().CreatePool(ctx, &store.BrokerPool{ID: string(pool), Name: "p", CreatedAt: time.Now().UTC()}, nil); err != nil {
		t.Fatal(err)
	}
	var asset store.Asset
	created(t, sendJSON(srv, admin, "POST", "/api/assets", `{"name":"dc1"}`), &asset)
	account := func(name, kind, ownerID string) string {
		t.Helper()
		body := `{"asset_id":"` + asset.ID + `","name":"` + name + `","account_kind":"` + kind + `"`
		if kind == "managed" {
			body += `,"pool_id":"` + string(pool) + `"`
		}
		if ownerID != "" {
			body += `,"owner_user_id":"` + ownerID + `"`
		}
		var a store.InventoryAccount
		created(t, sendJSON(srv, admin, "POST", "/api/accounts", body+`}`), &a)
		return a.ID
	}
	green := account("green", "managed", "usr_owner1")
	yellow := account("yellow", "vaulted", "usr_owner1")
	red := account("red", "managed", "")
	listedRed := account("listed", "managed", "")
	gone := account("gone", "vaulted", "usr_owner1")

	// green: a scheduled policy and a released rotation; listed: carol is an approver.
	key := pqcrypto.HexID(strings.Repeat("ab", 32))
	for _, id := range []string{green, listedRed} {
		raw, dg := d.SSHTarget(t, pqcrypto.UUID(id), pqcrypto.UUID(asset.ID), "h", 22, "root", key)
		if w := sendJSON(srv, admin, "PUT", "/api/accounts/"+id+"/target-descriptor", string(raw)); w.Code != http.StatusOK {
			t.Fatalf("descriptor: %d %s", w.Code, w.Body)
		}
		pol := d.ManagedPolicy(pqcrypto.UUID(id), pool, 1, dg)
		if id == green {
			pol.RotationSchedule = &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(time.Now().Add(-time.Hour)), IntervalSeconds: 86400}
		} else {
			pol.AllowedApproverPrincipalIDs = []pqcrypto.UUID{carolP.ID}
		}
		submit(d.Signed(t, pol))
	}
	seal := func(acct, receipt string) {
		t.Helper()
		v := st.Vault()
		op := "op-" + acct
		ver, err := v.Reserve(ctx, acct, op, 0)
		if err != nil {
			t.Fatal(err)
		}
		env := "env-" + acct
		if err := v.PutEnvelope(ctx, op, &store.StoredEnvelope{EnvelopeID: env, AccountID: acct, SecretVersion: ver, EnvelopeKind: "managed", Digest: "d-" + acct, Envelope: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
		rs := []*store.StoredReceipt{{EnvelopeID: env, ReceiptSeq: 1, ReceiptType: receipt, OperationID: op, Digest: "r1-" + acct, PrevReceiptHash: strings.Repeat("0", 64), Receipt: []byte("1")}}
		if receipt == "commit_target" {
			rs = append(rs, &store.StoredReceipt{EnvelopeID: env, ReceiptSeq: 2, ReceiptType: "release", OperationID: op, Digest: "r2-" + acct, PrevReceiptHash: "r1-" + acct, Receipt: []byte("2")})
		}
		if err := v.Complete(ctx, op, acct, rs, env, "", store.LockDelete); err != nil {
			t.Fatal(err)
		}
	}
	seal(green, "commit_target")
	seal(yellow, "vault_commit")
	if w := sendJSON(srv, admin, "PATCH", "/api/accounts/"+gone, `{"status":"decommissioned"}`); w.Code != http.StatusOK {
		t.Fatal(w.Code)
	}

	// The owner's department comes from SCIM (§8.2).
	dept, err := st.Inventory().EnsureDefinition(ctx, &store.AttributeDefinition{ID: string(pqtest.UUID()), Entity: store.EntityUser, Key: "department", Label: "Department", Type: store.AttrString, Source: store.SourceSCIM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Inventory().SetValue(ctx, dept.ID, "usr_owner1", "Ops", store.SourceSCIM, nil); err != nil {
		t.Fatal(err)
	}

	_, all := getCard(t, srv, admin, "")
	want := map[string]string{green: "green", yellow: "yellow", red: "red", listedRed: "red"}
	if all.Totals.Active != 4 || all.Totals.Decommissioned != 1 || len(all.Rows) != 4 {
		t.Fatalf("totals %+v", all.Totals)
	}
	for _, r := range all.Rows {
		if want[r.AccountID] != r.Class {
			t.Errorf("%s: class %s, want %s", r.AccountID, r.Class, want[r.AccountID])
		}
	}
	c := all.Totals.Classes
	if c["green"]+c["yellow"]+c["red"] != all.Totals.Active || c["green"] != 1 || c["yellow"] != 1 || c["red"] != 2 {
		t.Fatalf("classes %v", c)
	}
	if p := all.Totals.Percent; p["green"]+p["yellow"]+p["red"] != 100 {
		t.Fatalf("percent %v", p)
	}

	// One filter, three outputs, identical rows.
	q := "?owner.department=Ops"
	_, dash := getCard(t, srv, admin, q)
	wj, exp := getCard(t, srv, admin, q+"&format=json")
	if wj.Header().Get("Content-Disposition") == "" {
		t.Fatal("JSON export is not a download")
	}
	wc := sendJSON(srv, admin, "GET", "/api/reports/scorecard"+q+"&format=csv", "")
	recs, err := csv.NewReader(bytes.NewReader(wc.Body.Bytes())).ReadAll()
	if err != nil || wc.Code != http.StatusOK {
		t.Fatalf("csv %d %v", wc.Code, err)
	}
	if len(dash.Rows) != 2 || len(exp.Rows) != len(dash.Rows) || len(recs)-1 != len(dash.Rows) || dash.Totals.Active != exp.Totals.Active {
		t.Fatalf("dashboard %d rows, json %d, csv %d", len(dash.Rows), len(exp.Rows), len(recs)-1)
	}
	col := map[string]int{}
	for i, h := range recs[0] {
		col[h] = i
	}
	for i, r := range dash.Rows {
		if exp.Rows[i] != r || recs[i+1][col["account_id"]] != r.AccountID || recs[i+1][col["class"]] != r.Class ||
			recs[i+1][col["health"]] != r.Health || recs[i+1][col["owner.department"]] != "Ops" {
			t.Fatalf("row %d differs: %+v %+v %v", i, r, exp.Rows[i], recs[i+1])
		}
	}
	audits, _, _ := st.Audit().ListAuditRecords(ctx, 0, 100)
	exports := 0
	for _, a := range audits {
		if a.Action == "report.exported" {
			exports++
		}
	}
	if exports != 2 {
		t.Fatalf("%d export audit records, want 2", exports)
	}

	// A filter applies to the decommissioned count too.
	if _, c := getCard(t, srv, admin, "?owner.department=Sales"); c.Totals.Decommissioned != 0 {
		t.Fatalf("decommissioned outside the filter counted: %+v", c.Totals)
	}
	if _, c := getCard(t, srv, admin, "?class=green"); c.Totals.Decommissioned != 0 {
		t.Fatalf("decommissioned counted under a class filter: %+v", c.Totals)
	}
	if dash.Totals.Decommissioned != 1 {
		t.Fatalf("decommissioned under the owner's department: %+v", dash.Totals)
	}
	// The owner sees their two active accounts; carol sees only the one she approves.
	_, mine := getCard(t, srv, owner, "")
	if len(mine.Rows) != 2 || mine.Totals.Decommissioned != 1 {
		t.Fatalf("owner sees %+v", mine)
	}
	_, hers := getCard(t, srv, carolCookie, "")
	if len(hers.Rows) != 1 || hers.Rows[0].AccountID != listedRed {
		t.Fatalf("carol sees %+v", hers.Rows)
	}
	// dave has carol's subject from another identity provider: not her principal.
	dave := &store.User{ID: "usr_dave", Username: "dave", Role: "user", Status: "active", SSOProvider: "oidc", SSOSubject: carol.SSOSubject, SSOIssuer: "https://other-idp.example.test"}
	if err := st.Users().CreateUser(ctx, dave); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if _, _, err := auth.NewSessionManager(st, cfg.Security).IssueSession(ctx, rec, httptest.NewRequest("GET", "/", nil), dave); err != nil {
		t.Fatal(err)
	}
	if _, his := getCard(t, srv, rec.Result().Cookies()[0], ""); len(his.Rows) != 0 {
		t.Fatalf("dave sees %+v", his.Rows)
	}
	if w := sendJSON(srv, owner, "GET", "/api/jobs", ""); w.Code != http.StatusForbidden {
		t.Fatalf("jobs for a user: %d", w.Code)
	}
}
