package reporting

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
)

var t0 = time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)

func day() *pqcrypto.Schedule {
	return &pqcrypto.Schedule{AnchorUTC: pqcrypto.NewTime(t0), IntervalSeconds: 86400}
}

// §8.1: the class is decided by schedule + release, then a current envelope; health is an
// overlay and never changes the class.
func TestClassify(t *testing.T) {
	now := t0.Add(10 * 24 * time.Hour)
	for _, c := range []struct {
		name          string
		f             Facts
		class, health string
	}{
		{"listed", Facts{}, Red, Healthy},
		{"vaulted", Facts{CurrentSealed: true}, Yellow, Healthy},
		{"scheduled, never released", Facts{Schedule: day(), CurrentSealed: true}, Yellow, PendingFirstRotation},
		{"released, no schedule", Facts{LastRelease: now.Add(-time.Hour), CurrentSealed: true}, Yellow, Healthy},
		{"managed", Facts{Schedule: day(), LastRelease: now.Add(-time.Hour), CurrentSealed: true}, Green, Healthy},
		{"managed, overdue", Facts{Schedule: day(), LastRelease: now.Add(-50 * time.Hour), CurrentSealed: true}, Green, Overdue},
		{"latest occurrence due under one interval ago", Facts{Schedule: day(), LastRelease: now.Add(-23 * time.Hour), CurrentSealed: true}, Green, Healthy},
		{"quarantined stays green", Facts{Schedule: day(), LastRelease: now.Add(-time.Hour), CurrentSealed: true, BrokerHealth: Quarantined}, Green, Quarantined},
		{"checkout open", Facts{Schedule: day(), LastRelease: now.Add(-time.Hour), CurrentSealed: true, CheckoutLeases: 1}, Green, CheckoutOpen},
		{"auth failed beats checkout", Facts{CurrentSealed: true, BrokerHealth: AuthFailed, CheckoutLeases: 1}, Yellow, AuthFailed},
		{"release without a current envelope", Facts{Schedule: day(), LastRelease: now.Add(-time.Hour)}, Green, Healthy},
	} {
		class, health := Classify(c.f, now)
		if class != c.class || health != c.health {
			t.Errorf("%s: %s/%s, want %s/%s", c.name, class, health, c.class, c.health)
		}
	}
}

func TestPercentagesAlwaysSumTo100(t *testing.T) {
	for n := 1; n <= 40; n++ {
		for g := 0; g <= n; g++ {
			for y := 0; g+y <= n; y++ {
				var rows []*Row
				for i := 0; i < n; i++ {
					c := Red
					if i < g {
						c = Green
					} else if i < g+y {
						c = Yellow
					}
					rows = append(rows, &Row{Class: c, Health: Healthy})
				}
				s := Summarize(rows, 0)
				if s.Classes[Green]+s.Classes[Yellow]+s.Classes[Red] != n || s.Percent[Green]+s.Percent[Yellow]+s.Percent[Red] != 100 {
					t.Fatalf("n=%d g=%d y=%d: %+v", n, g, y, s)
				}
			}
		}
	}
}

func TestFilterAndCSV(t *testing.T) {
	rows := []*Row{
		{AccountID: "a", Name: "=cmd|' /C calc'!A0", Class: Green, Health: Healthy, PoolID: "p1", Attributes: map[string]string{"tier": "gold"}, OwnerAttributes: map[string]string{"department": "Ops"}},
		{AccountID: "b", Name: "svc", Class: Red, Health: Healthy, PoolID: "p2", Attributes: map[string]string{}, OwnerAttributes: map[string]string{"department": "Sales"}},
	}
	f := ParseFilter(map[string][]string{"owner.department": {"Ops"}, "attr.tier": {"gold"}, "pool": {"p1"}})
	if got := f.Apply(rows); len(got) != 1 || got[0].AccountID != "a" {
		t.Fatalf("filter %v", got)
	}
	if got := ParseFilter(map[string][]string{"class": {"red"}}).Apply(rows); len(got) != 1 || got[0].AccountID != "b" {
		t.Fatalf("class filter %v", got)
	}
	var b bytes.Buffer
	if err := WriteCSV(&b, &Dataset{AccountKeys: []string{"tier"}, OwnerKeys: []string{"department"}}, rows); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(lines) != 3 || !strings.HasSuffix(lines[0], ",attr.tier,owner.department") {
		t.Fatalf("csv %q", b.String())
	}
	if !strings.Contains(lines[1], `,'=cmd|' /C calc'!A0,`) || !strings.HasSuffix(lines[1], ",gold,Ops") {
		t.Fatalf("formula cell not neutralized: %q", lines[1])
	}
}

func TestSameIdentityNeedsIssuerAndSubject(t *testing.T) {
	ke := &pqcrypto.KeyEnrollmentManifest{Issuer: "https://idp.example.test", Subject: "s1"}
	for _, c := range []struct {
		caller Caller
		want   bool
	}{
		{Caller{Issuer: "https://idp.example.test", Subject: "s1"}, true},
		{Caller{Issuer: "https://other.example.test", Subject: "s1"}, false},
		{Caller{Subject: "s1"}, false},
		{Caller{Issuer: "https://idp.example.test", Subject: "s2"}, false},
	} {
		if got := sameIdentity(ke, c.caller); got != c.want {
			t.Errorf("%+v: %v", c.caller, got)
		}
	}
	if sameIdentity(&pqcrypto.KeyEnrollmentManifest{}, Caller{}) {
		t.Error("empty identities match")
	}
}
