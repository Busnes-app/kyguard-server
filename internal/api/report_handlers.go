package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/reporting"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

func (s *Server) reportRoutes() {
	// Reads only, so no step-up window. The dataset is authorized per caller (§8.3).
	s.route(ClassSession, "GET /api/reports/scorecard", http.HandlerFunc(s.requireSession(s.handleScorecard)))
	s.route(ClassSession, "GET /api/jobs", http.HandlerFunc(s.requireAdmin(s.handleJobs)))
}

// callerIssuer is the issuer of the caller's SSO identity (users.sso_issuer, §7.2), or ""
// for a local account, so a principal can never be matched to them by subject alone.
func callerIssuer(u *store.User) string {
	if u.SSOSubject == "" {
		return ""
	}
	return u.SSOIssuer
}

type scorecard struct {
	GeneratedAt time.Time        `json:"generated_at"`
	Totals      reporting.Totals `json:"totals"`
	AccountKeys []string         `json:"account_attribute_keys"`
	OwnerKeys   []string         `json:"owner_attribute_keys"`
	Rows        []*reporting.Row `json:"rows"`
}

// handleScorecard serves the dashboard (no format) and the exports (format=json|csv) from
// one dataset, one classifier and one filter (§8.3). Exports are downloads and audited.
func (s *Server) handleScorecard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	u, _, err := s.sessions.AuthenticateRequest(r)
	if err != nil {
		s.writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	q := r.URL.Query()
	format := q.Get("format")
	if format != "" && format != "json" && format != "csv" {
		s.writeError(w, http.StatusBadRequest, "format is json or csv")
		return
	}
	now := time.Now().UTC()
	ds, err := reporting.Build(ctx, s.store, s.trust, reporting.Caller{UserID: u.ID, Admin: u.Role == "admin", Issuer: callerIssuer(u), Subject: u.SSOSubject}, now)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not build the scorecard")
		return
	}
	f := reporting.ParseFilter(q)
	rows := f.Apply(ds.Rows)
	card := scorecard{GeneratedAt: now, Totals: reporting.Summarize(rows, f.Retired(ds.Retired)), AccountKeys: ds.AccountKeys, OwnerKeys: ds.OwnerKeys, Rows: rows}
	if format == "" {
		s.writeJSON(w, http.StatusOK, card)
		return
	}
	var body bytes.Buffer
	ctype := "application/json"
	if format == "csv" {
		ctype = "text/csv; charset=utf-8"
		err = reporting.WriteCSV(&body, ds, rows)
	} else {
		err = json.NewEncoder(&body).Encode(card)
	}
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not write the export")
		return
	}
	// The audit row lands before a byte of the export leaves (§8.3, §9.3).
	if err := s.store.Audit().LogAudit(ctx, s.audit(r, "report.exported", "scorecard",
		map[string]any{"format": format, "rows": len(rows), "filter": r.URL.Query().Encode()})); err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not audit the export")
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", `attachment; filename="kyguard-scorecard-`+now.Format("20060102T150405Z")+`.`+format+`"`)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body.Bytes())
}

// handleJobs lists recent rotation runs and checkout leases for the jobs screen (§10).
func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.Inventory().RecentRuns(r.Context(), 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list rotation runs")
		return
	}
	leases, err := s.store.Inventory().RecentLeases(r.Context(), 200)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list leases")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"runs": runs, "leases": leases})
}
