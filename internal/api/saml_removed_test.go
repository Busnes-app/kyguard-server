package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SAML cannot carry max_age and auth_time, so KyGuard removed it (spec §7.2, acceptance 15).
func TestSAMLRoutesAreGone(t *testing.T) {
	srv, _, _ := setupTestServer(t)
	for _, path := range []string{"/saml/metadata", "/saml/acs"} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, rec.Code)
		}
	}
}
