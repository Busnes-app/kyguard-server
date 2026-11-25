package scim

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	protocol "github.com/elimity-com/scim"
	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/store"
)

// SchemaEnterpriseUser is the Enterprise User extension (RFC 7643 §4.3). KyGuard syncs its
// department and manager, and the core title, into read-only user attributes (spec §8.2).
const SchemaEnterpriseUser = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"

// syncedKeys are the user attributes SCIM owns, with their labels.
var syncedKeys = map[string]string{"department": "Department", "manager": "Manager", "title": "Title"}

// attrChanges is what a request does to the synced attributes: a value, or nil to clear.
// A key that is absent is left alone.
type attrChanges map[string]*string

func ptr(s string) *string { return &s }

// fromResource reads the synced attributes of a full resource (create or PUT): every key is
// set, and an omitted one is cleared.
func fromResource(attrs protocol.ResourceAttributes) attrChanges {
	ch := attrChanges{"title": nil, "department": nil, "manager": nil}
	if v, ok := attrs["title"].(string); ok && v != "" {
		ch["title"] = ptr(v)
	}
	if ext, ok := attrs[SchemaEnterpriseUser].(map[string]interface{}); ok {
		ch.extension(ext)
	}
	return ch
}

// extension applies the values found in an Enterprise User object.
func (ch attrChanges) extension(ext map[string]interface{}) {
	for k, v := range ext {
		switch strings.ToLower(k) {
		case "department":
			ch.set("department", v)
		case "manager":
			// Only value is stored; a manager object without it (displayName, $ref) changes nothing.
			if m, ok := v.(map[string]interface{}); ok {
				if val, has := m["value"]; has {
					ch.set("manager", val)
				}
			} else {
				ch["manager"] = nil
			}
		}
	}
}

func (ch attrChanges) set(key string, v interface{}) {
	if s, ok := v.(string); ok && s != "" {
		ch[key] = ptr(s)
	} else {
		ch[key] = nil
	}
}

// fromPatch reads the synced attributes a PATCH touches, in operation order.
func fromPatch(ops []protocol.PatchOperation) attrChanges {
	ch := attrChanges{}
	for _, op := range ops {
		remove := op.Op == protocol.PatchOperationRemove
		if op.Path == nil {
			values, ok := op.Value.(map[string]interface{})
			if remove || !ok {
				continue
			}
			for k, v := range values {
				switch {
				case strings.EqualFold(k, "title"):
					ch.set("title", v)
				case strings.EqualFold(k, SchemaEnterpriseUser):
					if ext, ok := v.(map[string]interface{}); ok {
						ch.extension(ext)
					}
				case strings.HasPrefix(strings.ToLower(k), strings.ToLower(SchemaEnterpriseUser)+":"):
					ch.extension(map[string]interface{}{k[len(SchemaEnterpriseUser)+1:]: v})
				}
			}
			continue
		}
		p := op.Path.AttributePath
		name := strings.ToLower(p.AttributeName)
		uri := ""
		if p.URIPrefix != nil {
			uri = p.URI()
		}
		var key string
		switch {
		case uri == "" && name == "title":
			key = "title"
		case strings.EqualFold(uri, SchemaEnterpriseUser) && name == "department":
			key = "department"
		case strings.EqualFold(uri, SchemaEnterpriseUser) && name == "manager":
			key = "manager"
		default:
			continue
		}
		if p.SubAttribute != nil && !strings.EqualFold(*p.SubAttribute, "value") {
			continue // manager.displayName or manager.$ref: not stored
		}
		switch {
		case remove:
			ch[key] = nil
		case key == "manager" && p.SubAttribute == nil:
			if m, ok := op.Value.(map[string]interface{}); ok {
				if val, has := m["value"]; has {
					ch.set(key, val)
				}
			} else {
				ch.set(key, op.Value)
			}
		default: // manager.value or a plain string
			ch.set(key, op.Value)
		}
	}
	return ch
}

// clean bounds a directory value the way admin values are bounded: printable, ≤256.
func clean(s string) string {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) {
		return ""
	}
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > 256 {
		s = string([]rune(s)[:256])
	}
	return s
}

// syncAttributes writes the changes as SCIM-sourced user attributes. Each value is its own
// audited transaction; a failure fails the SCIM request so the IdP retries.
func syncAttributes(ctx context.Context, st store.Store, userID string, ch attrChanges) error {
	inv := st.Inventory()
	for _, key := range []string{"department", "manager", "title"} {
		v, touched := ch[key]
		if !touched {
			continue
		}
		d, err := inv.EnsureDefinition(ctx, &store.AttributeDefinition{ID: uuid.Must(uuid.NewV7()).String(), Entity: store.EntityUser, Key: key,
			Label: syncedKeys[key], Type: store.AttrString, Source: store.SourceSCIM},
			&store.AuditRecord{UserID: userID, Action: "attribute.definition_created", Resource: "attribute:user." + key, Details: "source=scim"})
		if err != nil {
			return err
		}
		val := ""
		if v != nil {
			val = clean(*v)
		}
		if err := inv.SetValue(ctx, d.ID, userID, val, store.SourceSCIM,
			&store.AuditRecord{UserID: userID, Action: "scim.user.attribute", Resource: "user:" + userID, Details: "key=" + key}); err != nil {
			return err
		}
	}
	return nil
}
