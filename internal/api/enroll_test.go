package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/ky-primitives/recoverykey"

	"github.com/Busnes-app/kyguard-server/internal/brokerproto"
	"github.com/Busnes-app/kyguard-server/internal/cli"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/pqtest"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func TestEnrollmentRoutes(t *testing.T) {
	srv, st, _, d := setupBrokerServer(t)
	ctx := context.Background()
	user := loginAs(t, srv, st, "enroller1", "user")
	submit := func(raw []byte) {
		t.Helper()
		if w := postJSON(srv, user, "/api/manifests", raw); w.Code != http.StatusCreated {
			t.Fatalf("manifest: %d %s", w.Code, w.Body)
		}
	}
	// One pool with an active broker, one account, alice may enroll.
	pool, acct, asset := pqtest.UUID(), pqtest.UUID(), pqtest.UUID()
	sig, _ := pqcrypto.GenerateSigningKey()
	enc, _ := recoverykey.Generate()
	b := &pqtest.Broker{ID: pqtest.UUID(), Sig: sig, Enc: enc, CertSHA256: pqcrypto.HexID(strings.Repeat("cd", 32))}
	submit(d.Pool(t, pool, 1, []pqcrypto.BrokerMember{b.Member(pqcrypto.StatusActive)}, nil))
	alice, bob := pqtest.NewPrincipal(t), pqtest.NewPrincipal(t)
	submit(d.Enrollment(t, alice, 1))
	submit(d.Enrollment(t, bob, 1))
	raw, dg := d.SSHTarget(t, acct, asset, "db1.example.test", 22, "svc", pqcrypto.HexID(strings.Repeat("ab", 32)))
	st.Guard().CreatePool(ctx, &store.BrokerPool{ID: string(pool), Name: "p", CreatedAt: time.Now().UTC()}, nil)
	st.Vault().CreateAsset(ctx, &store.Asset{ID: string(asset), Name: "h"})
	st.Vault().CreateAccount(ctx, &store.Account{ID: string(acct), AssetID: string(asset), Name: "svc", AccountKind: "managed", PoolID: string(pool)})
	st.Vault().PutTargetDescriptor(ctx, string(dg), string(acct), raw)
	pol := d.ManagedPolicy(acct, pool, 1, dg)
	pol.EnrollerPrincipalIDs = []pqcrypto.UUID{alice.ID}
	submit(d.Signed(t, pol))

	tr := d.Trust(t)
	ms, _ := st.Guard().Manifests(ctx, 0)
	for _, m := range ms {
		tr.Accept(m.Manifest)
	}
	reserve := func(who *pqtest.Principal, id pqcrypto.UUID) []byte {
		r, err := cli.SignReservation(tr, acct, id, who.ID, who.Sig, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(r)
		return b
	}
	base := "/api/accounts/" + string(acct) + "/enrollments"
	reqID := pqtest.UUID()
	if w := postJSON(srv, nil, base, reserve(alice, reqID)); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", w.Code)
	}
	// Security review of #15: a session that is not an enroller takes no lock.
	forged, _ := cli.SignReservation(tr, acct, reqID, alice.ID, bob.Sig, time.Now()) // claims alice, signed by bob
	forged.SigKeyID, _ = alice.Sig.Public().SigKeyID()
	forgedBody, _ := json.Marshal(forged)
	for name, body := range map[string][]byte{
		"forged":       forgedBody,
		"non-enroller": reserve(bob, reqID),
		"unsigned":     []byte(`{"request_id":"` + string(reqID) + `"}`),
	} {
		if w := postJSON(srv, user, base, body); w.Code != http.StatusForbidden {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		if op, _, _ := st.Vault().Lock(ctx, string(acct)); op != "" {
			t.Fatalf("%s took the lock", name)
		}
		if a, _ := st.Vault().GetAccount(ctx, string(acct)); a.HighestSecretVersion != 0 {
			t.Fatalf("%s allocated a version", name)
		}
	}
	w := postJSON(srv, user, base, reserve(alice, reqID))
	if w.Code != http.StatusCreated {
		t.Fatalf("reserve: %d %s", w.Code, w.Body)
	}
	var res struct {
		OperationID   string `json:"operation_id"`
		SecretVersion string `json:"secret_version"`
		BrokerID      string `json:"broker_id"`
	}
	json.Unmarshal(w.Body.Bytes(), &res)
	if res.SecretVersion != "1" || res.BrokerID != string(b.ID) {
		t.Fatalf("reservation %+v", res)
	}
	if w := postJSON(srv, user, base, reserve(alice, pqtest.UUID())); w.Code != http.StatusConflict {
		t.Fatalf("second reservation: %d", w.Code)
	}
	status := func() string {
		req := httptest.NewRequest("GET", base+"/"+string(reqID), nil)
		req.AddCookie(user)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		var s struct {
			State string `json:"state"`
		}
		json.Unmarshal(rec.Body.Bytes(), &s)
		return s.State
	}
	if s := status(); s != "reserved" {
		t.Fatalf("state %s", s)
	}

	good, err := cli.SealEnrollment(tr, acct, reqID, 1, alice.ID, alice.Sig, []byte("pw"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// bob re-signs alice's request: the Control Plane refuses it before storing anything.
	var tx pqcrypto.AccessTransaction
	pqtest.Decode(t, good.Tx, &tx)
	tx.RequesterPrincipalID, tx.Signatures = bob.ID, nil
	pqcrypto.Sign(&tx, pqcrypto.RoleUser, bob.Sig)
	body, _ := json.Marshal(brokerproto.EnrollPush{Tx: pqtest.Canon(t, &tx), Envelope: good.Envelope})
	if w := postJSON(srv, user, base+"/"+string(reqID), body); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), string(pqcrypto.ErrNotAllowed)) {
		t.Fatalf("outside the enrollers: %d %s", w.Code, w.Body)
	}
	if chains, _ := st.Vault().Chains(ctx, string(acct)); len(chains) != 0 {
		t.Fatal("a refused candidate was stored")
	}
	// Security review of #15: a broker-signed envelope is never a candidate, even under an
	// enroll signed over its digest.
	pd, _ := pqcrypto.ObjDigest(pol)
	bh := pqcrypto.Header{Type: pqcrypto.TypeEnvelope, DeploymentID: d.ID, Epoch: 1, Scope: pqcrypto.Scope{Kind: pqcrypto.ScopeAccount, ID: acct}, SignerRole: pqcrypto.RoleBroker}
	benv, _ := pqcrypto.Seal(bh, pqcrypto.KindManaged, pqtest.UUID(), 1, pd.Hex(), 0, time.Now(), []byte("x"), []pqcrypto.SealTo{{Type: pqcrypto.RecipientBroker, ID: string(b.ID), Pub: enc.Public().Bytes()}})
	pqcrypto.Sign(benv, pqcrypto.RoleBroker, sig)
	bd, _ := pqcrypto.ObjDigest(benv)
	_, btx := d.Tx(t, pol, b.ID, alice, pqcrypto.Action{ActionType: pqcrypto.ActionEnroll, EnvelopeDigest: bd.Hex(), SecretVersion: 1}, time.Now())
	btx.RequestID, btx.Signatures = reqID, nil
	pqcrypto.Sign(btx, pqcrypto.RoleUser, alice.Sig)
	body, _ = json.Marshal(brokerproto.EnrollPush{Tx: pqtest.Canon(t, btx), Envelope: pqtest.Canon(t, benv)})
	if w := postJSON(srv, user, base+"/"+string(reqID), body); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("broker-signed candidate: %d %s", w.Code, w.Body)
	}
	body, _ = json.Marshal(brokerproto.EnrollPush{Tx: good.Tx, Envelope: good.Envelope})
	// No broker is connected in this test: the candidate is stored and the CLI retries.
	if w := postJSON(srv, user, base+"/"+string(reqID), body); w.Code != http.StatusServiceUnavailable {
		t.Fatalf("submit: %d %s", w.Code, w.Body)
	}
	if chains, _ := st.Vault().Chains(ctx, string(acct)); len(chains) != 1 || chains[0].Envelope.SecretVersion != 1 {
		t.Fatalf("candidate not stored: %+v", chains)
	}
}
