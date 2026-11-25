package cptrust

import "testing"

// The equivocation alert names the manifest type; submitted text never reaches the log.
func TestLogTypeKeepsSubmittedTextOutOfTheLog(t *testing.T) {
	for in, want := range map[string]string{"pool": "pool", "policy": "policy", "pool\n[TRUST] forged": "unknown", "": "unknown"} {
		if got := logType(in); got != want {
			t.Errorf("logType(%q) = %q, want %q", in, got, want)
		}
	}
}
