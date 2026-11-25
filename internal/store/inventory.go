package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// ErrInvalid means a write names something that does not exist or breaks a definition's
// rules (an enum value outside its list, an unknown owner, a SCIM-owned attribute).
var ErrInvalid = errors.New("invalid inventory write")

// Attribute entities, types and sources (spec §8.2).
const (
	EntityAccount = "account"
	EntityUser    = "user"
	AttrString    = "string"
	AttrEnum      = "enum"
	SourceAdmin   = "admin"
	SourceSCIM    = "scim"
)

// InventoryStore holds the account inventory and attributes (spec §8.2, §10). Every write
// audits in its own transaction.
type InventoryStore interface {
	ListAssets(ctx context.Context) ([]*Asset, error)
	CreateAsset(ctx context.Context, a *Asset, audit *AuditRecord) error
	// CreateAccount adds a listed account; the owner, when set, must be a user.
	CreateAccount(ctx context.Context, a *InventoryAccount, audit *AuditRecord) error
	// UpdateAccount sets only the fields p names, in one statement, so concurrent patches
	// to different fields never undo each other. It returns the stored account; ErrNotFound
	// for an unknown account.
	UpdateAccount(ctx context.Context, id string, p AccountPatch, audit *AuditRecord) (*InventoryAccount, error)
	GetAccount(ctx context.Context, id string) (*InventoryAccount, error)
	ListAccounts(ctx context.Context) ([]*InventoryAccount, error)
	// PutDescriptor stores a verified target descriptor's canonical bytes for its account;
	// storing it again is a no-op.
	PutDescriptor(ctx context.Context, digest, accountID string, canonical []byte, audit *AuditRecord) error
	// Descriptors returns every stored descriptor of the account, newest first.
	Descriptors(ctx context.Context, accountID string) ([]*StoredDescriptor, error)

	Definitions(ctx context.Context, entity string) ([]*AttributeDefinition, error)
	// EnsureDefinition creates d unless (entity, key) exists and returns the stored one.
	EnsureDefinition(ctx context.Context, d *AttributeDefinition, audit *AuditRecord) (*AttributeDefinition, error)
	// UpdateDefinition changes the label and enum values of an admin definition; nil
	// EnumValues keeps the stored list. An enum value still in use cannot be removed (ErrConflict).
	UpdateDefinition(ctx context.Context, d *AttributeDefinition, audit *AuditRecord) error
	// DeleteDefinition removes an admin definition and its values.
	DeleteDefinition(ctx context.Context, id string, audit *AuditRecord) error
	// SetValue writes one value as source; "" deletes it. The definition's source must be
	// source, so an admin never edits a SCIM attribute and SCIM never edits an admin one.
	SetValue(ctx context.Context, definitionID, entityID, value, source string, audit *AuditRecord) error
	// Values maps entity ID to attribute key to value for one entity type.
	Values(ctx context.Context, entity string) (map[string]map[string]string, error)
}

// InventoryAccount is an account row with its inventory columns.
type InventoryAccount struct {
	Account
	AssetName   string `json:"asset_name"`
	OwnerUserID string `json:"owner_user_id"`
	// MinPasswordAgeSeconds is what the broker last reported (§4.4); nil when unknown.
	MinPasswordAgeSeconds *int64 `json:"min_password_age_seconds"`
}

// StoredDescriptor is a target descriptor as uploaded.
type StoredDescriptor struct {
	Digest     string
	AccountID  string
	Descriptor []byte
	CreatedAt  time.Time
}

// AttributeDefinition is one attribute (§8.2). EnumValues is set only for enum types.
type AttributeDefinition struct {
	ID         string    `json:"id"`
	Entity     string    `json:"entity"`
	Key        string    `json:"key"`
	Label      string    `json:"label"`
	Type       string    `json:"type"`
	EnumValues []string  `json:"enum_values"`
	Source     string    `json:"source"`
	CreatedAt  time.Time `json:"created_at"`
}

type inventoryStore struct{ s *SQLStore }

func (s *SQLStore) Inventory() InventoryStore { return inventoryStore{s} }

func (v inventoryStore) ListAssets(ctx context.Context) ([]*Asset, error) {
	rows, err := v.s.db.QueryContext(ctx, `SELECT id, name, created_at FROM assets ORDER BY name, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Asset{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Name, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &a)
	}
	return out, rows.Err()
}

func (v inventoryStore) CreateAsset(ctx context.Context, a *Asset, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		a.CreatedAt = time.Now().UTC()
		if _, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO assets (id, name, created_at) VALUES (?, ?, ?)`), a.ID, a.Name, a.CreatedAt); err != nil {
			return uniqueErr(err)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

// exists reports whether table has a row with id = id inside tx.
func (v inventoryStore) exists(ctx context.Context, tx *sql.Tx, table, id string) (bool, error) {
	var n int
	err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT COUNT(1) FROM `+table+` WHERE id = ?`), id).Scan(&n)
	return n > 0, err
}

func (v inventoryStore) checkRefs(ctx context.Context, tx *sql.Tx, a *InventoryAccount) error {
	if a.OwnerUserID != "" {
		if ok, err := v.exists(ctx, tx, "users", a.OwnerUserID); err != nil || !ok {
			return errors.Join(err, ErrInvalid)
		}
	}
	if a.PoolID != "" {
		if ok, err := v.exists(ctx, tx, "broker_pools", a.PoolID); err != nil || !ok {
			return errors.Join(err, ErrInvalid)
		}
	}
	return nil
}

func (v inventoryStore) CreateAccount(ctx context.Context, a *InventoryAccount, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		if ok, err := v.exists(ctx, tx, "assets", a.AssetID); err != nil || !ok {
			return errors.Join(err, ErrInvalid)
		}
		if err := v.checkRefs(ctx, tx, a); err != nil {
			return err
		}
		a.Status, a.CreatedAt = "active", time.Now().UTC()
		_, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO accounts (id, asset_id, name, account_kind, pool_id, owner_user_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`),
			a.ID, a.AssetID, a.Name, a.AccountKind, nullable(a.PoolID), nullable(a.OwnerUserID), a.CreatedAt)
		if err != nil {
			return uniqueErr(err)
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

// AccountPatch names the account fields a PATCH changes; nil leaves a field as stored.
type AccountPatch struct{ Name, OwnerUserID, Status *string }

func (v inventoryStore) UpdateAccount(ctx context.Context, id string, p AccountPatch, audit *AuditRecord) (*InventoryAccount, error) {
	var out *InventoryAccount
	err := v.s.inTx(ctx, func(tx *sql.Tx) error {
		set, args := "id = id", []any{}
		if p.Name != nil {
			set, args = set+", name = ?", append(args, *p.Name)
		}
		if p.OwnerUserID != nil {
			if err := v.checkRefs(ctx, tx, &InventoryAccount{OwnerUserID: *p.OwnerUserID}); err != nil {
				return err
			}
			set, args = set+", owner_user_id = ?", append(args, nullable(*p.OwnerUserID))
		}
		if p.Status != nil {
			set, args = set+", status = ?", append(args, *p.Status)
		}
		res, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE accounts SET `+set+` WHERE id = ?`), append(args, id)...)
		if err != nil {
			return err
		}
		if n, err := res.RowsAffected(); err != nil || n == 0 {
			return errors.Join(err, ErrNotFound)
		}
		if out, err = scanInventory(tx.QueryRowContext(ctx, v.s.rebind(`SELECT `+inventoryCols+` FROM accounts a JOIN assets s ON s.id = a.asset_id WHERE a.id = ?`), id)); err != nil {
			return err
		}
		return v.s.auditTx(ctx, tx, audit)
	})
	return out, err
}

const inventoryCols = `a.id, a.asset_id, a.name, a.account_kind, COALESCE(a.pool_id, ''), a.status, COALESCE(a.current_envelope_id, ''),
	a.highest_secret_version, a.health, a.health_reason, a.created_at, s.name, COALESCE(a.owner_user_id, ''), a.min_password_age_seconds`

func scanInventory(row interface{ Scan(...any) error }) (*InventoryAccount, error) {
	var a InventoryAccount
	var hv int64
	var age sql.NullInt64
	err := row.Scan(&a.ID, &a.AssetID, &a.Name, &a.AccountKind, &a.PoolID, &a.Status, &a.CurrentEnvelopeID, &hv,
		&a.Health, &a.HealthReason, &a.CreatedAt, &a.AssetName, &a.OwnerUserID, &age)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	a.HighestSecretVersion = uint64(hv)
	if age.Valid {
		a.MinPasswordAgeSeconds = &age.Int64
	}
	return &a, err
}

func (v inventoryStore) GetAccount(ctx context.Context, id string) (*InventoryAccount, error) {
	return scanInventory(v.s.db.QueryRowContext(ctx, v.s.rebind(`SELECT `+inventoryCols+` FROM accounts a JOIN assets s ON s.id = a.asset_id WHERE a.id = ?`), id))
}

func (v inventoryStore) ListAccounts(ctx context.Context) ([]*InventoryAccount, error) {
	rows, err := v.s.db.QueryContext(ctx, `SELECT `+inventoryCols+` FROM accounts a JOIN assets s ON s.id = a.asset_id ORDER BY s.name, a.name, a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*InventoryAccount{}
	for rows.Next() {
		a, err := scanInventory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (v inventoryStore) PutDescriptor(ctx context.Context, digest, accountID string, canonical []byte, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		var owner string
		err := tx.QueryRowContext(ctx, v.s.rebind(`SELECT account_id FROM target_descriptors WHERE digest = ?`), digest).Scan(&owner)
		if err == nil {
			if owner != accountID {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO target_descriptors (digest, account_id, descriptor, created_at) VALUES (?, ?, ?, ?)`),
			digest, accountID, string(canonical), time.Now().UTC()); err != nil {
			return err
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v inventoryStore) Descriptors(ctx context.Context, accountID string) ([]*StoredDescriptor, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT digest, account_id, descriptor, created_at FROM target_descriptors WHERE account_id = ? ORDER BY created_at DESC, digest`), accountID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*StoredDescriptor{}
	for rows.Next() {
		var d StoredDescriptor
		var raw string
		if err := rows.Scan(&d.Digest, &d.AccountID, &raw, &d.CreatedAt); err != nil {
			return nil, err
		}
		d.Descriptor = []byte(raw)
		out = append(out, &d)
	}
	return out, rows.Err()
}

const definitionCols = `id, entity, key, label, type, enum_values, source, created_at`

func scanDefinition(row interface{ Scan(...any) error }) (*AttributeDefinition, error) {
	var d AttributeDefinition
	var enum string
	err := row.Scan(&d.ID, &d.Entity, &d.Key, &d.Label, &d.Type, &enum, &d.Source, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(enum), &d.EnumValues); err != nil {
		return nil, err
	}
	return &d, nil
}

func (v inventoryStore) Definitions(ctx context.Context, entity string) ([]*AttributeDefinition, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT `+definitionCols+` FROM attribute_definitions WHERE entity = ? ORDER BY key`), entity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AttributeDefinition{}
	for rows.Next() {
		d, err := scanDefinition(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (v inventoryStore) definition(ctx context.Context, tx *sql.Tx, id string) (*AttributeDefinition, error) {
	q := `SELECT ` + definitionCols + ` FROM attribute_definitions WHERE id = ?`
	if v.s.driver == "postgres" {
		q += ` FOR UPDATE`
	}
	return scanDefinition(tx.QueryRowContext(ctx, v.s.rebind(q), id))
}

func enumJSON(d *AttributeDefinition) (string, error) {
	vals := d.EnumValues
	if d.Type != AttrEnum || vals == nil {
		vals = []string{}
	}
	b, err := json.Marshal(vals)
	return string(b), err
}

func (v inventoryStore) EnsureDefinition(ctx context.Context, d *AttributeDefinition, audit *AuditRecord) (*AttributeDefinition, error) {
	var out *AttributeDefinition
	err := v.s.inTx(ctx, func(tx *sql.Tx) error {
		got, err := scanDefinition(tx.QueryRowContext(ctx, v.s.rebind(`SELECT `+definitionCols+` FROM attribute_definitions WHERE entity = ? AND key = ?`), d.Entity, d.Key))
		if err == nil {
			out = got
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		enum, err := enumJSON(d)
		if err != nil {
			return err
		}
		d.CreatedAt = time.Now().UTC()
		if _, err := tx.ExecContext(ctx, v.s.rebind(`INSERT INTO attribute_definitions (`+definitionCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`),
			d.ID, d.Entity, d.Key, d.Label, d.Type, enum, d.Source, d.CreatedAt); err != nil {
			return uniqueErr(err)
		}
		out = d
		return v.s.auditTx(ctx, tx, audit)
	})
	return out, err
}

func (v inventoryStore) UpdateDefinition(ctx context.Context, d *AttributeDefinition, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		cur, err := v.definition(ctx, tx, d.ID)
		if err != nil {
			return err
		}
		if cur.Source != SourceAdmin {
			return ErrInvalid
		}
		if d.EnumValues == nil {
			d.EnumValues = cur.EnumValues
		}
		if cur.Type == AttrEnum {
			rows, err := tx.QueryContext(ctx, v.s.rebind(`SELECT DISTINCT value FROM attribute_values WHERE definition_id = ?`), d.ID)
			if err != nil {
				return err
			}
			var used []string
			for rows.Next() {
				var s string
				if err := rows.Scan(&s); err != nil {
					rows.Close()
					return err
				}
				used = append(used, s)
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for _, u := range used {
				if !slices.Contains(d.EnumValues, u) {
					return ErrConflict
				}
			}
		}
		d.Type = cur.Type
		enum, err := enumJSON(d)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`UPDATE attribute_definitions SET label = ?, enum_values = ? WHERE id = ?`), d.Label, enum, d.ID); err != nil {
			return err
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v inventoryStore) DeleteDefinition(ctx context.Context, id string, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		cur, err := v.definition(ctx, tx, id)
		if err != nil {
			return err
		}
		if cur.Source != SourceAdmin {
			return ErrInvalid
		}
		// Explicit, not only ON DELETE CASCADE, so the values go even where foreign keys are off.
		if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM attribute_values WHERE definition_id = ?`), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, v.s.rebind(`DELETE FROM attribute_definitions WHERE id = ?`), id); err != nil {
			return err
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v inventoryStore) SetValue(ctx context.Context, definitionID, entityID, value, source string, audit *AuditRecord) error {
	return v.s.inTx(ctx, func(tx *sql.Tx) error {
		d, err := v.definition(ctx, tx, definitionID)
		if errors.Is(err, ErrNotFound) {
			return ErrInvalid
		}
		if err != nil {
			return err
		}
		if d.Source != source || (value != "" && d.Type == AttrEnum && !slices.Contains(d.EnumValues, value)) {
			return ErrInvalid
		}
		table := "accounts"
		if d.Entity == EntityUser {
			table = "users"
		}
		if ok, err := v.exists(ctx, tx, table, entityID); err != nil || !ok {
			return errors.Join(err, ErrInvalid)
		}
		var prev string
		err = tx.QueryRowContext(ctx, v.s.rebind(`SELECT value FROM attribute_values WHERE definition_id = ? AND entity_id = ?`), definitionID, entityID).Scan(&prev)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			if value == "" {
				return nil
			}
			_, err = tx.ExecContext(ctx, v.s.rebind(`INSERT INTO attribute_values (definition_id, entity_id, value, updated_at) VALUES (?, ?, ?, ?)`), definitionID, entityID, value, time.Now().UTC())
		case err != nil:
			return err
		case prev == value:
			return nil
		case value == "":
			_, err = tx.ExecContext(ctx, v.s.rebind(`DELETE FROM attribute_values WHERE definition_id = ? AND entity_id = ?`), definitionID, entityID)
		default:
			_, err = tx.ExecContext(ctx, v.s.rebind(`UPDATE attribute_values SET value = ?, updated_at = ? WHERE definition_id = ? AND entity_id = ?`), value, time.Now().UTC(), definitionID, entityID)
		}
		if err != nil {
			return err
		}
		return v.s.auditTx(ctx, tx, audit)
	})
}

func (v inventoryStore) Values(ctx context.Context, entity string) (map[string]map[string]string, error) {
	rows, err := v.s.db.QueryContext(ctx, v.s.rebind(`SELECT v.entity_id, d.key, v.value FROM attribute_values v JOIN attribute_definitions d ON d.id = v.definition_id WHERE d.entity = ?`), entity)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]string{}
	for rows.Next() {
		var id, key, val string
		if err := rows.Scan(&id, &key, &val); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]string{}
		}
		out[id][key] = val
	}
	return out, rows.Err()
}
