// Package reporting builds the traffic-light scorecard (spec §8.1–§8.3): one authorized
// dataset, one classifier and one filter, shared by the dashboard and the CSV and JSON
// exports.
package reporting

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Busnes-app/kyguard-server/internal/cptrust"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// Classes (§8.1).
const (
	Green  = "green"  // managed: active schedule and at least one release
	Yellow = "yellow" // vaulted: a sealed current envelope
	Red    = "red"    // listed, not controlled
)

// Health values (§8.1). The broker reports the first five; the rest are derived here.
const (
	Healthy              = "healthy"
	PendingFirstRotation = "pending_first_rotation"
	Overdue              = "overdue"
	RotationFailed       = "rotation_failed"
	AuthFailed           = "auth_failed"
	Quarantined          = "quarantined"
	NeedsEnrollment      = "needs_enrollment"
	CheckoutOpen         = "checkout_open"
)

// Caller is who asks. Admins see every account; anyone else sees the accounts they own or
// are listed on in the current policy (§8.3). Issuer and Subject name the caller's SSO
// identity; a principal counts as the caller only when its verified KeyEnrollmentManifest
// names that same non-empty pair.
type Caller struct {
	UserID          string
	Admin           bool
	Issuer, Subject string
}

// Facts are the stored inputs the classifier reads for one account.
type Facts struct {
	Active         bool
	Kind           string
	Schedule       *pqcrypto.Schedule // from the current verified policy; nil when none
	LastRelease    time.Time          // newest release receipt; zero when none
	CurrentSealed  bool               // a current envelope exists (§3.5)
	BrokerHealth   string             // as the broker last reported it
	CheckoutLeases int                // non-closed leases
}

// Classify returns the class and the health overlay (§8.1). Facts must be of an active
// account; decommissioned accounts are not classified.
func Classify(f Facts, now time.Time) (class, health string) {
	switch {
	case f.Schedule != nil && !f.LastRelease.IsZero():
		class = Green
	case f.CurrentSealed:
		class = Yellow
	default:
		class = Red
	}
	switch {
	case f.BrokerHealth != "" && f.BrokerHealth != Healthy:
		health = f.BrokerHealth
	case f.CheckoutLeases > 0:
		health = CheckoutOpen
	case f.Schedule != nil && f.LastRelease.IsZero():
		health = PendingFirstRotation
	case f.Schedule != nil && overdue(*f.Schedule, f.LastRelease, now):
		health = Overdue
	default:
		health = Healthy
	}
	return class, health
}

// overdue reports a due occurrence not run within one interval: the latest occurrence due
// at or before now - interval came after the last release.
func overdue(s pqcrypto.Schedule, last, now time.Time) bool {
	if s.IntervalSeconds <= 0 {
		return false
	}
	iv := time.Duration(s.IntervalSeconds) * time.Second
	cutoff := now.Add(-iv)
	if cutoff.Before(s.AnchorUTC.Time) {
		return false
	}
	k := cutoff.Sub(s.AnchorUTC.Time) / iv
	due := s.AnchorUTC.Add(k * iv)
	return last.Before(due)
}

// Row is one account in the scorecard.
type Row struct {
	AccountID             string            `json:"account_id"`
	Asset                 string            `json:"asset"`
	Name                  string            `json:"name"`
	Kind                  string            `json:"account_kind"`
	PoolID                string            `json:"pool_id"`
	Class                 string            `json:"class"`
	Health                string            `json:"health"`
	HealthReason          string            `json:"health_reason"`
	OwnerUserID           string            `json:"owner_user_id"`
	Owner                 string            `json:"owner"`
	MinPasswordAgeSeconds *int64            `json:"min_password_age_seconds"`
	DescriptorDigest      string            `json:"target_descriptor_digest"`
	LastRelease           *time.Time        `json:"last_release"`
	Attributes            map[string]string `json:"attributes"`
	OwnerAttributes       map[string]string `json:"owner_attributes"`
}

// Dataset is the authorized scorecard dataset: active rows and the visible decommissioned
// count, which no class includes (§8.1).
type Dataset struct {
	Rows           []*Row
	Decommissioned int
	AccountKeys    []string // account attribute keys, sorted
	OwnerKeys      []string // user attribute keys, sorted
}

// Build reads the inventory and the verified policies once and returns what caller may see.
func Build(ctx context.Context, st store.Store, trust *cptrust.Trust, caller Caller, now time.Time) (*Dataset, error) {
	inv := st.Inventory()
	accounts, err := inv.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	facts, err := inv.ReportFacts(ctx)
	if err != nil {
		return nil, err
	}
	acctVals, err := inv.Values(ctx, store.EntityAccount)
	if err != nil {
		return nil, err
	}
	userVals, err := inv.Values(ctx, store.EntityUser)
	if err != nil {
		return nil, err
	}
	policies := map[string]*pqcrypto.PolicyManifest{}
	mine := map[pqcrypto.UUID]bool{} // the caller's principals
	err = trust.View(ctx, func(tr *pqcrypto.Trust) error {
		for _, a := range accounts {
			if p, _ := tr.Policy(pqcrypto.UUID(a.ID)); p != nil {
				policies[a.ID] = p
			}
		}
		if caller.Admin || caller.Issuer == "" || caller.Subject == "" {
			return nil
		}
		for _, r := range tr.Records() {
			if r.Type != pqcrypto.TypeKeyEnrollment {
				continue
			}
			if ke := tr.Enrollment(r.ScopeID); ke != nil && sameIdentity(ke, caller) {
				mine[ke.PrincipalID] = true
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, cptrust.ErrNoBundle) {
		return nil, err
	}

	ds := &Dataset{Rows: []*Row{}}
	owners := map[string]string{}
	akeys, okeys := map[string]bool{}, map[string]bool{}
	for _, a := range accounts {
		p := policies[a.ID]
		if !caller.Admin && a.OwnerUserID != caller.UserID && !listed(p, mine) {
			continue
		}
		if a.Status != "active" {
			ds.Decommissioned++
			continue
		}
		f := facts[a.ID]
		if f == nil {
			f = &store.ReportFacts{}
		}
		in := Facts{Active: true, Kind: a.AccountKind, LastRelease: f.LastRelease, CurrentSealed: a.CurrentEnvelopeID != "",
			BrokerHealth: a.Health, CheckoutLeases: f.OpenLeases}
		row := &Row{AccountID: a.ID, Asset: a.AssetName, Name: a.Name, Kind: a.AccountKind, PoolID: a.PoolID, HealthReason: a.HealthReason,
			OwnerUserID: a.OwnerUserID, MinPasswordAgeSeconds: a.MinPasswordAgeSeconds, Attributes: nonNil(acctVals[a.ID]), OwnerAttributes: map[string]string{}}
		if p != nil {
			in.Schedule = p.RotationSchedule
			row.DescriptorDigest = string(p.TargetDescriptorDigest)
		}
		if !f.LastRelease.IsZero() {
			lr := f.LastRelease
			row.LastRelease = &lr
		}
		row.Class, row.Health = Classify(in, now)
		if a.OwnerUserID != "" {
			row.OwnerAttributes = nonNil(userVals[a.OwnerUserID])
			name, ok := owners[a.OwnerUserID]
			if !ok {
				if u, err := st.Users().GetUserByID(ctx, a.OwnerUserID); err == nil {
					name = u.Username
				} else if !errors.Is(err, store.ErrNotFound) {
					return nil, err
				}
				owners[a.OwnerUserID] = name
			}
			row.Owner = name
		}
		for k := range row.Attributes {
			akeys[k] = true
		}
		for k := range row.OwnerAttributes {
			okeys[k] = true
		}
		ds.Rows = append(ds.Rows, row)
	}
	ds.AccountKeys, ds.OwnerKeys = slices.Sorted(maps.Keys(akeys)), slices.Sorted(maps.Keys(okeys))
	return ds, nil
}

func nonNil(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// sameIdentity reports whether a verified key enrollment names the caller: the same
// non-empty issuer and subject, never the subject alone (§7.2).
func sameIdentity(ke *pqcrypto.KeyEnrollmentManifest, c Caller) bool {
	return c.Issuer != "" && c.Subject != "" && ke.Issuer == c.Issuer && ke.Subject == c.Subject
}

// listed reports whether one of the caller's principals is named anywhere in the policy.
func listed(p *pqcrypto.PolicyManifest, mine map[pqcrypto.UUID]bool) bool {
	if p == nil || len(mine) == 0 {
		return false
	}
	for _, l := range [][]pqcrypto.UUID{p.AllowedUserPrincipalIDs, p.AllowedApproverPrincipalIDs, p.EnrollerPrincipalIDs, p.StandingRecipientPrincipalIDs} {
		for _, id := range l {
			if mine[id] {
				return true
			}
		}
	}
	return false
}

// Filter is equality on class, health, pool and attributes (§8.3). Empty fields match all.
type Filter struct {
	Class, Health, Pool string
	Attributes          map[string]string // account attribute key -> value
	OwnerAttributes     map[string]string // owner's user attribute key -> value
}

// ParseFilter reads class, health, pool, attr.<key> and owner.<key> from a query.
func ParseFilter(q map[string][]string) Filter {
	f := Filter{Attributes: map[string]string{}, OwnerAttributes: map[string]string{}}
	for k, v := range q {
		if len(v) == 0 {
			continue
		}
		switch {
		case k == "class":
			f.Class = v[0]
		case k == "health":
			f.Health = v[0]
		case k == "pool":
			f.Pool = v[0]
		case strings.HasPrefix(k, "attr."):
			f.Attributes[strings.TrimPrefix(k, "attr.")] = v[0]
		case strings.HasPrefix(k, "owner."):
			f.OwnerAttributes[strings.TrimPrefix(k, "owner.")] = v[0]
		}
	}
	return f
}

// Match applies the filter to one row.
func (f Filter) Match(r *Row) bool {
	if (f.Class != "" && r.Class != f.Class) || (f.Health != "" && r.Health != f.Health) || (f.Pool != "" && r.PoolID != f.Pool) {
		return false
	}
	for k, v := range f.Attributes {
		if r.Attributes[k] != v {
			return false
		}
	}
	for k, v := range f.OwnerAttributes {
		if r.OwnerAttributes[k] != v {
			return false
		}
	}
	return true
}

// Apply returns the rows the filter matches, in order.
func (f Filter) Apply(rows []*Row) []*Row {
	out := []*Row{}
	for _, r := range rows {
		if f.Match(r) {
			out = append(out, r)
		}
	}
	return out
}

// Totals are the dashboard numbers for a set of rows. Percent values are whole percents
// that sum to 100 whenever Active > 0.
type Totals struct {
	Active         int            `json:"active"`
	Decommissioned int            `json:"decommissioned"`
	Classes        map[string]int `json:"classes"`
	Percent        map[string]int `json:"percent"`
	Health         map[string]int `json:"health"`
}

// Summarize counts classes and health. Decommissioned is passed through from the dataset.
func Summarize(rows []*Row, decommissioned int) Totals {
	t := Totals{Active: len(rows), Decommissioned: decommissioned, Classes: map[string]int{Green: 0, Yellow: 0, Red: 0},
		Percent: map[string]int{Green: 0, Yellow: 0, Red: 0}, Health: map[string]int{}}
	for _, r := range rows {
		t.Classes[r.Class]++
		t.Health[r.Health]++
	}
	if t.Active > 0 {
		// Largest remainder, so the three always add up to 100.
		order := []string{Green, Yellow, Red}
		used := 0
		rem := map[string]int{}
		for _, c := range order {
			t.Percent[c] = t.Classes[c] * 100 / t.Active
			rem[c] = t.Classes[c] * 100 % t.Active
			used += t.Percent[c]
		}
		slices.SortStableFunc(order, func(a, b string) int { return rem[b] - rem[a] })
		for i := 0; used < 100; i++ {
			t.Percent[order[i%3]]++
			used++
		}
	}
	return t
}

// WriteCSV writes rows with the fixed columns, then attr.<key> and owner.<key> columns.
// Cells that a spreadsheet would read as a formula are prefixed with a quote.
func WriteCSV(w io.Writer, ds *Dataset, rows []*Row) error {
	cw := csv.NewWriter(w)
	head := []string{"account_id", "asset", "account", "account_kind", "pool_id", "class", "health", "health_reason",
		"owner", "owner_user_id", "min_password_age_seconds", "target_descriptor_digest", "last_release"}
	for _, k := range ds.AccountKeys {
		head = append(head, "attr."+k)
	}
	for _, k := range ds.OwnerKeys {
		head = append(head, "owner."+k)
	}
	if err := cw.Write(head); err != nil {
		return err
	}
	for _, r := range rows {
		age, last := "", ""
		if r.MinPasswordAgeSeconds != nil {
			age = strconv.FormatInt(*r.MinPasswordAgeSeconds, 10)
		}
		if r.LastRelease != nil {
			last = r.LastRelease.UTC().Format(time.RFC3339)
		}
		rec := []string{r.AccountID, r.Asset, r.Name, r.Kind, r.PoolID, r.Class, r.Health, r.HealthReason,
			r.Owner, r.OwnerUserID, age, r.DescriptorDigest, last}
		for _, k := range ds.AccountKeys {
			rec = append(rec, r.Attributes[k])
		}
		for _, k := range ds.OwnerKeys {
			rec = append(rec, r.OwnerAttributes[k])
		}
		for i, c := range rec {
			rec[i] = cell(c)
		}
		if err := cw.Write(rec); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func cell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}
