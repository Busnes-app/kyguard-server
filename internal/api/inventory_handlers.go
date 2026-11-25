package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Busnes-app/kyguard-server/internal/pqcrypto"
	"github.com/Busnes-app/kyguard-server/internal/pqcrypto/canonical"
	"github.com/Busnes-app/kyguard-server/internal/store"
)

// scimUserKeys are the user attributes SCIM owns (spec §8.2); an admin cannot define them.
var scimUserKeys = []string{"department", "manager", "title"}

var attrKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

func (s *Server) inventoryRoutes() {
	// TODO(hawthorn §7.5): classify + step-up. Inventory and attribute writes are admin only.
	s.mux.HandleFunc("GET /api/assets", s.requireAdmin(s.handleListAssets))
	s.mux.HandleFunc("POST /api/assets", s.requireAdmin(s.handleCreateAsset))
	s.mux.HandleFunc("POST /api/accounts", s.requireAdmin(s.handleCreateAccount))
	s.mux.HandleFunc("GET /api/accounts", s.requireAdmin(s.handleListAccounts))
	s.mux.HandleFunc("GET /api/accounts/{id}", s.requireAdmin(s.handleGetAccount))
	s.mux.HandleFunc("PATCH /api/accounts/{id}", s.requireAdmin(s.handleUpdateAccount))
	// TODO(hawthorn §7.5): classify + fresh(StepupWindow): a descriptor is what a policy pins.
	s.mux.HandleFunc("PUT /api/accounts/{id}/target-descriptor", s.requireAdmin(s.handlePutDescriptor))
	// Definitions are labels only; every signed-in user's report filters read them.
	s.mux.HandleFunc("GET /api/attributes", s.requireAuthenticated(s.handleListAttributes))
	s.mux.HandleFunc("POST /api/attributes", s.requireAdmin(s.handleCreateAttribute))
	s.mux.HandleFunc("PATCH /api/attributes/{id}", s.requireAdmin(s.handleUpdateAttribute))
	s.mux.HandleFunc("DELETE /api/attributes/{id}", s.requireAdmin(s.handleDeleteAttribute))
	s.mux.HandleFunc("PUT /api/attributes/{id}/values/{entity}", s.requireAdmin(s.handleSetAttributeValue))
}

// decodeStrict reads one JSON object with no unknown fields.
func decodeStrict(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// cleanText trims s and accepts 1..max printable characters.
func cleanText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || utf8.RuneCountInString(s) > max || !utf8.ValidString(s) {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", false
		}
	}
	return s, true
}

func (s *Server) audit(r *http.Request, action, resource string, details map[string]any) *store.AuditRecord {
	return &store.AuditRecord{UserID: s.actor(r), Action: action, Resource: resource, Details: AuditDetails(details), IPAddress: s.requestIP(r)}
}

func (s *Server) inventoryError(w http.ResponseWriter, err error, what string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		s.writeError(w, http.StatusNotFound, what+" not found")
	case errors.Is(err, store.ErrInvalid):
		s.writeError(w, http.StatusBadRequest, "invalid "+what)
	case errors.Is(err, store.ErrAlreadyExists), errors.Is(err, store.ErrConflict):
		s.writeError(w, http.StatusConflict, what+" conflicts with the stored one")
	default:
		s.writeError(w, http.StatusInternalServerError, "could not save the "+what)
	}
}

func newID() string { return uuid.Must(uuid.NewV7()).String() }

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.store.Inventory().ListAssets(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list assets")
		return
	}
	s.writeJSON(w, http.StatusOK, assets)
}

func (s *Server) handleCreateAsset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	name, ok := "", false
	if decodeStrict(r, &req) == nil {
		name, ok = cleanText(req.Name, 128)
	}
	if !ok {
		s.writeError(w, http.StatusBadRequest, "name is required (at most 128 characters)")
		return
	}
	a := &store.Asset{ID: newID(), Name: name}
	if err := s.store.Inventory().CreateAsset(r.Context(), a, s.audit(r, "inventory.asset_created", "asset:"+a.ID, map[string]any{"name": name})); err != nil {
		s.inventoryError(w, err, "asset")
		return
	}
	s.writeJSON(w, http.StatusCreated, a)
}

type accountRequest struct {
	AssetID     *string `json:"asset_id"`
	Name        *string `json:"name"`
	AccountKind *string `json:"account_kind"`
	PoolID      *string `json:"pool_id"`
	OwnerUserID *string `json:"owner_user_id"`
	Status      *string `json:"status"`
}

func (s *Server) handleCreateAccount(w http.ResponseWriter, r *http.Request) {
	var req accountRequest
	if err := decodeStrict(r, &req); err != nil || req.AssetID == nil || req.Name == nil || req.AccountKind == nil || req.Status != nil {
		s.writeError(w, http.StatusBadRequest, "asset_id, name and account_kind are required")
		return
	}
	name, ok := cleanText(*req.Name, 128)
	if !ok || (*req.AccountKind != pqcrypto.KindManaged && *req.AccountKind != pqcrypto.KindVaulted) {
		s.writeError(w, http.StatusBadRequest, "name (at most 128 characters) and account_kind managed or vaulted are required")
		return
	}
	a := &store.InventoryAccount{Account: store.Account{ID: newID(), AssetID: *req.AssetID, Name: name, AccountKind: *req.AccountKind}}
	if req.PoolID != nil {
		a.PoolID = *req.PoolID
	}
	if req.OwnerUserID != nil {
		a.OwnerUserID = *req.OwnerUserID
	}
	if err := s.store.Inventory().CreateAccount(r.Context(), a, s.audit(r, "inventory.account_created", "account:"+a.ID,
		map[string]any{"name": name, "kind": a.AccountKind, "asset": a.AssetID, "owner": a.OwnerUserID})); err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	s.writeJSON(w, http.StatusCreated, a)
}

func (s *Server) handleUpdateAccount(w http.ResponseWriter, r *http.Request) {
	var req accountRequest
	if err := decodeStrict(r, &req); err != nil || req.AssetID != nil || req.AccountKind != nil || req.PoolID != nil {
		s.writeError(w, http.StatusBadRequest, "only name, owner_user_id and status can change")
		return
	}
	p, detail := store.AccountPatch{OwnerUserID: req.OwnerUserID, Status: req.Status}, map[string]any{}
	if req.Name != nil {
		name, ok := cleanText(*req.Name, 128)
		if !ok {
			s.writeError(w, http.StatusBadRequest, "name must be 1 to 128 characters")
			return
		}
		p.Name, detail["name"] = &name, name
	}
	if req.OwnerUserID != nil {
		detail["owner"] = *req.OwnerUserID
	}
	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "decommissioned" {
			s.writeError(w, http.StatusBadRequest, "status is active or decommissioned")
			return
		}
		detail["status"] = *req.Status
	}
	id := r.PathValue("id")
	a, err := s.store.Inventory().UpdateAccount(r.Context(), id, p, s.audit(r, "inventory.account_updated", "account:"+id, detail))
	if err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	s.writeJSON(w, http.StatusOK, a)
}

type descriptorView struct {
	Digest                      string `json:"digest"`
	ConnectorType               string `json:"connector_type"`
	AuthenticatedTargetIdentity string `json:"authenticated_target_identity"`
	Host                        string `json:"host"`
	Port                        int    `json:"port"`
	// TLSCASHA256 is the SHA-256 of the pinned CA PEM, so the screen shows a digest.
	TLSCASHA256      string `json:"tls_ca_sha256,omitempty"`
	SSHHostKeySHA256 string `json:"ssh_host_key_sha256,omitempty"`
}

func viewDescriptor(d *store.StoredDescriptor) (*descriptorView, error) {
	td, _, err := pqcrypto.DecodeTargetDescriptor(d.Descriptor)
	if err != nil {
		return nil, err
	}
	v := &descriptorView{Digest: d.Digest, ConnectorType: td.ConnectorType, AuthenticatedTargetIdentity: td.AuthenticatedTargetIdentity,
		Host: td.Endpoint.Host, Port: td.Endpoint.Port, SSHHostKeySHA256: td.Endpoint.SSHHostKeySHA256}
	if td.Endpoint.TLSCAPEM != "" {
		v.TLSCASHA256 = sha256Hex([]byte(td.Endpoint.TLSCAPEM))
	}
	return v, nil
}

func (s *Server) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := s.store.Inventory().GetAccount(ctx, r.PathValue("id"))
	if err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	stored, err := s.store.Inventory().Descriptors(ctx, a.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read descriptors")
		return
	}
	descs := []*descriptorView{}
	for _, d := range stored {
		v, err := viewDescriptor(d)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "a stored descriptor no longer decodes")
			return
		}
		descs = append(descs, v)
	}
	attrs, err := s.store.Inventory().EntityValues(ctx, store.EntityAccount, a.ID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not read attributes")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"account": a, "descriptors": descs, "attributes": attrs})
}

// handlePutDescriptor stores a target descriptor for the account (spec §3.3). The Control
// Plane rejects out-of-slice descriptors and ones naming another deployment, account or asset.
func (s *Server) handlePutDescriptor(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a, err := s.store.Inventory().GetAccount(ctx, r.PathValue("id"))
	if err != nil {
		s.inventoryError(w, err, "account")
		return
	}
	if a.AccountKind != pqcrypto.KindManaged {
		s.writeError(w, http.StatusBadRequest, "only managed accounts have a target descriptor")
		return
	}
	bundle, err := s.store.Guard().Bundle(ctx)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "import the bootstrap bundle first (kyguard-server import-bundle)")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64<<10))
	if err != nil {
		s.writeError(w, http.StatusRequestEntityTooLarge, "descriptor over 64 KiB")
		return
	}
	td, digest, err := pqcrypto.DecodeTargetDescriptor(raw)
	if errors.Is(err, pqcrypto.ErrUnsupported) {
		s.writeError(w, http.StatusBadRequest, "descriptor is outside the Phase 1A slice (ad_ldaps or ssh_passwd, empty connector_config and dependencies)")
		return
	}
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "descriptor does not decode")
		return
	}
	if string(td.DeploymentID) != bundle.DeploymentID || string(td.AccountID) != a.ID || string(td.AssetID) != a.AssetID {
		s.writeError(w, http.StatusBadRequest, "descriptor names another deployment, account or asset")
		return
	}
	canon, err := canonical.Canonicalize(raw)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "descriptor does not decode")
		return
	}
	dg := string(digest.Hex())
	if err := s.store.Inventory().PutDescriptor(ctx, dg, a.ID, canon, s.audit(r, "inventory.descriptor_uploaded", "account:"+a.ID,
		map[string]any{"digest": dg, "connector": td.ConnectorType, "host": td.Endpoint.Host})); err != nil {
		s.inventoryError(w, err, "descriptor")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"digest": dg})
}

func (s *Server) handleListAttributes(w http.ResponseWriter, r *http.Request) {
	out := map[string][]*store.AttributeDefinition{}
	for _, e := range []string{store.EntityAccount, store.EntityUser} {
		defs, err := s.store.Inventory().Definitions(r.Context(), e)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "could not list attributes")
			return
		}
		out[e] = defs
	}
	s.writeJSON(w, http.StatusOK, out)
}

// cleanEnum validates an enum list: 1..64 distinct values of 1..128 characters.
func cleanEnum(in []string) ([]string, bool) {
	if len(in) == 0 || len(in) > 64 {
		return nil, false
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		c, ok := cleanText(v, 128)
		if !ok || slices.Contains(out, c) {
			return nil, false
		}
		out = append(out, c)
	}
	return out, true
}

func (s *Server) handleCreateAttribute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Entity     string   `json:"entity"`
		Key        string   `json:"key"`
		Label      string   `json:"label"`
		Type       string   `json:"type"`
		EnumValues []string `json:"enum_values"`
	}
	if err := decodeStrict(r, &req); err != nil || (req.Entity != store.EntityAccount && req.Entity != store.EntityUser) || !attrKey.MatchString(req.Key) {
		s.writeError(w, http.StatusBadRequest, "entity (account or user) and key (lowercase letters, digits, _) are required")
		return
	}
	if req.Entity == store.EntityUser && slices.Contains(scimUserKeys, req.Key) {
		s.writeError(w, http.StatusBadRequest, "department, manager and title are synced from SCIM")
		return
	}
	label, ok := cleanText(req.Label, 128)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "label must be 1 to 128 characters")
		return
	}
	d := &store.AttributeDefinition{ID: newID(), Entity: req.Entity, Key: req.Key, Label: label, Type: req.Type, Source: store.SourceAdmin}
	switch req.Type {
	case store.AttrString:
		if req.EnumValues != nil {
			ok = false
		}
	case store.AttrEnum:
		d.EnumValues, ok = cleanEnum(req.EnumValues)
	default:
		ok = false
	}
	if !ok {
		s.writeError(w, http.StatusBadRequest, "type is string, or enum with 1 to 64 distinct values")
		return
	}
	got, err := s.store.Inventory().EnsureDefinition(r.Context(), d, s.audit(r, "attribute.definition_created", "attribute:"+d.ID,
		map[string]any{"entity": d.Entity, "key": d.Key, "type": d.Type}))
	if err == nil && got.ID != d.ID {
		err = store.ErrAlreadyExists
	}
	if err != nil {
		s.inventoryError(w, err, "attribute")
		return
	}
	s.writeJSON(w, http.StatusCreated, d)
}

func (s *Server) handleUpdateAttribute(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Label      string   `json:"label"`
		EnumValues []string `json:"enum_values"`
	}
	label, ok := "", false
	if decodeStrict(r, &req) == nil {
		label, ok = cleanText(req.Label, 128)
	}
	d := &store.AttributeDefinition{ID: r.PathValue("id"), Label: label}
	if ok && req.EnumValues != nil {
		d.EnumValues, ok = cleanEnum(req.EnumValues)
	}
	if !ok {
		s.writeError(w, http.StatusBadRequest, "label (1 to 128 characters) and, for an enum, its values are required")
		return
	}
	if err := s.store.Inventory().UpdateDefinition(r.Context(), d, s.audit(r, "attribute.definition_updated", "attribute:"+d.ID,
		map[string]any{"label": label, "enum_values": strings.Join(d.EnumValues, ",")})); err != nil {
		if errors.Is(err, store.ErrConflict) {
			s.writeError(w, http.StatusConflict, "an enum value still in use cannot be removed")
			return
		}
		s.inventoryError(w, err, "attribute")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"id": d.ID})
}

func (s *Server) handleDeleteAttribute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.store.Inventory().DeleteDefinition(r.Context(), id, s.audit(r, "attribute.definition_deleted", "attribute:"+id, nil)); err != nil {
		s.inventoryError(w, err, "attribute")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleSetAttributeValue sets an admin attribute on an account or user; "" clears it.
// SCIM-sourced attributes are read-only here (§8.2): the store refuses them.
func (s *Server) handleSetAttributeValue(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Value *string `json:"value"`
	}
	// value must be present: "" clears, but a missing or null value is a mistake, not a delete.
	if err := decodeStrict(r, &req); err != nil || req.Value == nil {
		s.writeError(w, http.StatusBadRequest, "value is required (\"\" clears it)")
		return
	}
	value := strings.TrimSpace(*req.Value)
	if value != "" {
		var ok bool
		if value, ok = cleanText(value, 256); !ok {
			s.writeError(w, http.StatusBadRequest, "value must be at most 256 printable characters")
			return
		}
	}
	id, entity := r.PathValue("id"), r.PathValue("entity")
	if err := s.store.Inventory().SetValue(r.Context(), id, entity, value, store.SourceAdmin, s.audit(r, "attribute.value_set", "attribute:"+id,
		map[string]any{"entity": entity, "value": value})); err != nil {
		s.inventoryError(w, err, "attribute value")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]string{"value": value})
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// handleListAccounts lists inventory rows by status (default active) so admins can reach a
// decommissioned account, which the scorecard counts but never lists (spec §8.1).
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "active"
	}
	if status != "active" && status != "decommissioned" {
		s.writeError(w, http.StatusBadRequest, "status is active or decommissioned")
		return
	}
	all, err := s.store.Inventory().ListAccounts(r.Context())
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "could not list accounts")
		return
	}
	out := []*store.InventoryAccount{}
	for _, a := range all {
		if a.Status == status {
			out = append(out, a)
		}
	}
	s.writeJSON(w, http.StatusOK, out)
}
