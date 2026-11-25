package store

import (
	"context"
	"errors"
	"testing"
)

func inventoryFor(t *testing.T) (*SQLStore, InventoryStore) {
	t.Helper()
	s, _ := guardStoreFor(t)
	inv := s.Inventory()
	ctx := context.Background()
	if err := s.Users().CreateUser(ctx, &User{ID: "usr_a", Username: "alice", Role: "user", Status: "active", SSOProvider: "local"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.CreateAsset(ctx, &Asset{ID: "as", Name: "dc1"}, &AuditRecord{Action: "inventory.asset_created"}); err != nil {
		t.Fatal(err)
	}
	if err := inv.CreateAccount(ctx, &InventoryAccount{Account: Account{ID: "ac", AssetID: "as", Name: "svc", AccountKind: "managed"}, OwnerUserID: "usr_a"}, &AuditRecord{Action: "inventory.account_created"}); err != nil {
		t.Fatal(err)
	}
	return s, inv
}

func TestAccountOwnerMustBeAUser(t *testing.T) {
	_, inv := inventoryFor(t)
	ctx := context.Background()
	a, err := inv.GetAccount(ctx, "ac")
	if err != nil || a.OwnerUserID != "usr_a" || a.AssetName != "dc1" || a.Status != "active" {
		t.Fatalf("account %+v %v", a, err)
	}
	ghost := "usr_nobody"
	if _, err := inv.UpdateAccount(ctx, a.ID, AccountPatch{OwnerUserID: &ghost}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown owner: %v", err)
	}
	if err := inv.CreateAccount(ctx, &InventoryAccount{Account: Account{ID: "ac2", AssetID: "missing", Name: "x", AccountKind: "vaulted"}}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown asset: %v", err)
	}
}

// An admin write never touches a SCIM attribute, and an enum takes only its listed values.
func TestAttributeValuesFollowTheirDefinition(t *testing.T) {
	_, inv := inventoryFor(t)
	ctx := context.Background()
	dept, err := inv.EnsureDefinition(ctx, &AttributeDefinition{ID: "d1", Entity: EntityUser, Key: "department", Label: "Department", Type: AttrString, Source: SourceSCIM}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetValue(ctx, dept.ID, "usr_a", "Ops", SourceAdmin, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("admin wrote a SCIM attribute: %v", err)
	}
	if err := inv.SetValue(ctx, dept.ID, "usr_a", "Ops", SourceSCIM, nil); err != nil {
		t.Fatal(err)
	}
	if err := inv.DeleteDefinition(ctx, dept.ID, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SCIM definition deleted: %v", err)
	}

	tier, err := inv.EnsureDefinition(ctx, &AttributeDefinition{ID: "d2", Entity: EntityAccount, Key: "tier", Label: "Tier", Type: AttrEnum, EnumValues: []string{"gold", "silver"}, Source: SourceAdmin}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.SetValue(ctx, tier.ID, "ac", "bronze", SourceAdmin, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("value outside the enum: %v", err)
	}
	if err := inv.SetValue(ctx, tier.ID, "usr_a", "gold", SourceAdmin, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("account attribute on a user: %v", err)
	}
	if err := inv.SetValue(ctx, tier.ID, "ac", "gold", SourceAdmin, nil); err != nil {
		t.Fatal(err)
	}
	tier.EnumValues = []string{"silver"}
	if err := inv.UpdateDefinition(ctx, tier, nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("removed an enum value in use: %v", err)
	}
	// A label-only change keeps the stored choices, in use or not.
	for _, id := range []string{tier.ID, "d3"} {
		if id == "d3" {
			if _, err := inv.EnsureDefinition(ctx, &AttributeDefinition{ID: id, Entity: EntityAccount, Key: "zone", Label: "Zone", Type: AttrEnum, EnumValues: []string{"a", "b"}, Source: SourceAdmin}, nil); err != nil {
				t.Fatal(err)
			}
		}
		if err := inv.UpdateDefinition(ctx, &AttributeDefinition{ID: id, Label: "Renamed"}, nil); err != nil {
			t.Fatalf("label-only update of %s: %v", id, err)
		}
	}
	if defs, _ := inv.Definitions(ctx, EntityAccount); len(defs) != 2 || len(defs[0].EnumValues) != 2 || len(defs[1].EnumValues) != 2 {
		t.Fatalf("label-only update changed the choices: %+v %+v", defs[0], defs[1])
	}
	vals, err := inv.Values(ctx, EntityAccount)
	if err != nil || vals["ac"]["tier"] != "gold" {
		t.Fatalf("values %v %v", vals, err)
	}
	if u, _ := inv.Values(ctx, EntityUser); u["usr_a"]["department"] != "Ops" {
		t.Fatalf("user values %v", u)
	}
	if err := inv.DeleteDefinition(ctx, tier.ID, nil); err != nil {
		t.Fatal(err)
	}
	if vals, _ := inv.Values(ctx, EntityAccount); len(vals) != 0 {
		t.Fatalf("values outlived their definition: %v", vals)
	}
}

// A patch writes only the fields it names, so a name change never restores a stale owner
// or status written by a concurrent patch.
func TestAccountPatchWritesOnlyItsFields(t *testing.T) {
	_, inv := inventoryFor(t)
	ctx := context.Background()
	gone := "decommissioned"
	if _, err := inv.UpdateAccount(ctx, "ac", AccountPatch{Status: &gone}, nil); err != nil {
		t.Fatal(err)
	}
	name := "svc2"
	a, err := inv.UpdateAccount(ctx, "ac", AccountPatch{Name: &name}, nil)
	if err != nil || a.Name != "svc2" || a.Status != "decommissioned" || a.OwnerUserID != "usr_a" {
		t.Fatalf("account %+v %v", a, err)
	}
	none := ""
	if a, err := inv.UpdateAccount(ctx, "ac", AccountPatch{OwnerUserID: &none}, nil); err != nil || a.OwnerUserID != "" || a.Name != "svc2" {
		t.Fatalf("clear owner %+v %v", a, err)
	}
	if _, err := inv.UpdateAccount(ctx, "missing", AccountPatch{Name: &name}, nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}

// A failed audit write rolls the inventory change back (§9.3).
func TestInventoryWriteRollsBackWithItsAudit(t *testing.T) {
	s, inv := inventoryFor(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `DROP TABLE audit_records`); err != nil {
		t.Fatal(err)
	}
	if err := inv.CreateAsset(ctx, &Asset{ID: "as2", Name: "dc2"}, &AuditRecord{Action: "inventory.asset_created"}); err == nil {
		t.Fatal("asset created without its audit record")
	}
	assets, err := inv.ListAssets(ctx)
	if err != nil || len(assets) != 1 {
		t.Fatalf("assets %v %v", assets, err)
	}
}
