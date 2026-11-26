package api_test

import (
	"net/http"
	"strings"
	"testing"
)

// reportingSessionRoutes are the reporting routes open to any session (method and path).
var reportingSessionRoutes = [][2]string{{"GET", "/api/attributes"},
	{"GET", "/api/reports/scorecard"}, {"GET", "/api/reports/scorecard?format=json"}, {"GET", "/api/reports/scorecard?format=csv"}}

// Spec §7.4: a break-glass session reads no reporting data until it states its reason.
func TestReportingRoutesWaitForBreakGlassReason(t *testing.T) {
	srv, st, _, _ := setupBrokerServer(t)
	bg := newBreakGlass(t, srv, st, "bgreport")
	w := loginWithCode(t, srv, bg.Username, bg.Password, bg.Code(t), "192.0.2.9:1")
	session := sessionCookie(w)
	if w.Code != http.StatusOK || session == nil {
		t.Fatalf("login: %d", w.Code)
	}
	for _, rt := range reportingSessionRoutes {
		if w := sendJSON(srv, session, rt[0], rt[1], ""); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "break_glass_reason_required") {
			t.Fatalf("%v before the reason: %d %s", rt, w.Code, w.Body)
		}
	}
	if w := sendJSON(srv, session, "POST", "/api/auth/break-glass/reason", `{"reason":"audit"}`); w.Code != http.StatusOK {
		t.Fatalf("reason: %d %s", w.Code, w.Body)
	}
	for _, rt := range reportingSessionRoutes {
		if w := sendJSON(srv, session, rt[0], rt[1], ""); w.Code == http.StatusForbidden || w.Code == http.StatusUnauthorized {
			t.Fatalf("%v after the reason: %d %s", rt, w.Code, w.Body)
		}
	}
}
