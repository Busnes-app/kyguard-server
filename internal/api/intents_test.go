package api_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/Busnes-app/ky-primitives/recoveryclient"
	"github.com/Busnes-app/ky-primitives/recoverykey"
	"github.com/Busnes-app/kyguard-server/internal/api"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// intentSpy records the intents a handler begins; failSettle makes every completion append
// fail, as a broken audit log would.
type intentSpy struct {
	store.Store
	begun      *[]string
	failSettle bool
}

func (s intentSpy) Intents() store.IntentStore {
	return spyIntents{s.Store.Intents(), s.begun, s.failSettle}
}

type spyIntents struct {
	store.IntentStore
	begun *[]string
	fail  bool
}

func (s spyIntents) Begin(ctx context.Context, kind, subject string) (string, error) {
	id, err := s.IntentStore.Begin(ctx, kind, subject)
	*s.begun = append(*s.begun, id)
	return id, err
}

func (s spyIntents) Settle(ctx context.Context, id, state string, r *store.AuditRecord) error {
	if s.fail {
		return errors.New("audit write failed")
	}
	return s.IntentStore.Settle(ctx, id, state, r)
}

func newestAction(t *testing.T, st store.Store) string {
	t.Helper()
	recs, _, err := st.Audit().ListAuditRecords(context.Background(), 0, 1)
	if err != nil || len(recs) == 0 {
		t.Fatal(recs, err)
	}
	return recs[0].Action
}

// §9.3: a recovery-key pin commits an intent first; its audit record is the completion
// append, and when that append fails the pin answers 500 and the intent stays pending.
func TestPinKeySettlesItsIntent(t *testing.T) {
	for _, broken := range []bool{false, true} {
		srv, st, _ := setupTestServer(t)
		session := loginAs(t, srv, st, "alice", "admin")
		var begun []string
		api.SetStoreForTest(srv, intentSpy{st, &begun, broken})
		priv, _ := recoverykey.Generate()
		w := adminDo(t, srv, session, "POST", "/api/backup/pin-key", pinBody(priv.Public(), 2, 3))
		if len(begun) != 1 {
			t.Fatalf("broken=%v: %d intents begun", broken, len(begun))
		}
		in, err := st.Intents().Get(context.Background(), begun[0])
		if err != nil || in.Kind != "pin" {
			t.Fatal(in, err)
		}
		if broken {
			if w.Code != http.StatusInternalServerError || in.State != store.IntentPending {
				t.Fatalf("pin with a failing audit: %d %s, intent %s", w.Code, w.Body, in.State)
			}
			continue
		}
		if w.Code != http.StatusOK || in.State != store.IntentComplete || newestAction(t, st) != "admin.backup_key_pin" {
			t.Fatalf("pin: %d %s, intent %s", w.Code, w.Body, in.State)
		}
	}
}

// lostAnswerPairer is KyRecovery spending the code and the answer never arriving. It checks
// that the claim's intent was durable before the claim went out.
type lostAnswerPairer struct {
	fakePairer
	t     *testing.T
	st    store.Store
	begun *[]string
}

func (p lostAnswerPairer) ClaimPairing(context.Context, string, string, string, string) (recoveryclient.PairingResult, error) {
	if len(*p.begun) != 1 {
		p.t.Error("the claim went out with no intent")
	} else if in, err := p.st.Intents().Get(context.Background(), (*p.begun)[0]); err != nil || in.State != store.IntentPending {
		p.t.Errorf("the claim went out with intent %+v %v", in, err)
	}
	return recoveryclient.PairingResult{}, errors.New("connection reset")
}

// §9.3: a pairing claim whose answer was lost ends outcome_unknown, with its audit record.
func TestLostPairingClaimEndsOutcomeUnknown(t *testing.T) {
	srv, st, _ := setupTestServer(t)
	session := loginAs(t, srv, st, "alice", "admin")
	var begun []string
	api.SetStoreForTest(srv, intentSpy{st, &begun, false})
	api.SetRecoveryClientForTest(srv, lostAnswerPairer{t: t, st: st, begun: &begun})
	w := adminDo(t, srv, session, "POST", "/api/backup/pair-remote", map[string]string{"recovery_url": "https://recovery.busnes.app", "pairing_code": "123456"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("lost claim: %d %s", w.Code, w.Body)
	}
	if in, err := st.Intents().Get(context.Background(), begun[0]); err != nil || in.State != store.IntentUnknown || in.Kind != "pairing" {
		t.Fatalf("intent %+v %v, want pairing outcome_unknown", in, err)
	}
	if got := newestAction(t, st); got != "backup.pair_failed" {
		t.Fatalf("newest record %s", got)
	}
}
