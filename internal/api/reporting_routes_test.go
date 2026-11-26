package api_test

import (
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/api"
)

// §7.3 rule 6, §7.5: the report and policy-draft routes are session class; saving and
// deleting a draft need a step-up within five minutes, the reads and signing none
// (decisions 205-212).
func TestReportingRoutesAreClassifiedWithTheirWindows(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	want := map[string]time.Duration{
		"GET /api/reports/scorecard":              0,
		"GET /api/jobs":                           0,
		"PUT /api/accounts/{id}/policy-draft":     api.StepupWindow,
		"DELETE /api/policy-drafts/{id}":          api.StepupWindow,
		"GET /api/policy-drafts":                  0,
		"GET /api/policy-drafts/{id}":             0,
		"POST /api/policy-drafts/{id}/signatures": 0,
		"GET /api/principals":                     0,
		"GET /api/trust":                          0,
	}
	for _, r := range srv.Routes() {
		fresh, ok := want[r.Pattern]
		if !ok {
			continue
		}
		delete(want, r.Pattern)
		if r.Class != api.ClassSession || r.Fresh != fresh {
			t.Errorf("%s: class %q window %v, want session %v", r.Pattern, r.Class, r.Fresh, fresh)
		}
	}
	for pattern := range want {
		t.Errorf("%s is not registered", pattern)
	}
}
