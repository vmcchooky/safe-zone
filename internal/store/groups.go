package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"

	"safe-zone/internal/analysis"
	"safe-zone/internal/logjson"
)

// Multi-tenant policy groups, client mappings and group overrides live here.
// sqlite.go keeps connection lifecycle, schema/migrations, telemetry,
// retention/vacuum, whitelist, reports and config. Split roadmap: telemetry
// queries, whitelist, reports and retention move out next, one domain per
// file, same package, no API change.

// ClientGroup represents a policy group for clients.
type ClientGroup struct {
	ID              int64    `json:"id"`
	Name            string   `json:"name"`
	Description     string   `json:"description"`
	BlockCategories []string `json:"block_categories"` // stored as JSON array in SQLite
	StrictPhishing  bool     `json:"strict_phishing"`
	StrictMalware   bool     `json:"strict_malware"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// ClientMapping represents a mapping of a client device to a policy group.
type ClientMapping struct {
	ID          int64  `json:"id"`
	MappingType string `json:"mapping_type"` // "ip", "cidr", "client_id"
	Value       string `json:"value"`
	GroupID     int64  `json:"group_id"`
	GroupName   string `json:"group_name,omitempty"` // populated during joins
	CreatedAt   string `json:"created_at"`
}

// GroupOverride represents a manual override rule specific to a policy group.
type GroupOverride struct {
	ID        int64  `json:"id"`
	GroupID   int64  `json:"group_id"`
	Domain    string `json:"domain"`
	Action    string `json:"action"` // "allow", "block"
	Reason    string `json:"reason"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type cidrMapping struct {
	groupID int64
	ipNet   *net.IPNet
}

// --- Multi-Tenant CRUD and Dynamic Mapping Methods ---

// CreateDefaultGroups auto-initializes the core 'default' policy group.
func (d *DB) CreateDefaultGroups(ctx context.Context) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	var exists int
	err := d.db.QueryRowContext(ctx, "SELECT 1 FROM client_groups WHERE name = 'default'").Scan(&exists)
	if err == sql.ErrNoRows {
		_, err = d.db.ExecContext(ctx, `
			INSERT INTO client_groups (name, description, block_categories, strict_phishing, strict_malware)
			VALUES ('default', 'Default policy group', '[]', 0, 1)`)
		if err != nil {
			return fmt.Errorf("insert default group: %w", err)
		}
		logjson.Info("sqlite store initialized default policy group", map[string]any{
			"service": "store",
			"group":   "default",
		})
		return nil
	}
	return err
}

// CreateGroup creates a new client policy group.
// ErrGroupNotFound and ErrMappingNotFound let the API distinguish "no such row"
// (404) from "the store could not answer" (503). Returning one message for both
// made a disabled store indistinguishable from a mistyped id.
var (
	ErrGroupNotFound   = errors.New("group not found")
	ErrMappingNotFound = errors.New("mapping not found")
)

func (d *DB) CreateGroup(ctx context.Context, name, description string, blockCategories []string, strictPhishing, strictMalware bool) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	blockCatsJSON, err := json.Marshal(blockCategories)
	if err != nil {
		return 0, fmt.Errorf("marshal block categories: %w", err)
	}

	sp := 0
	if strictPhishing {
		sp = 1
	}
	sm := 0
	if strictMalware {
		sm = 1
	}

	res, err := d.db.ExecContext(ctx, `
		INSERT INTO client_groups (name, description, block_categories, strict_phishing, strict_malware)
		VALUES (?, ?, ?, ?, ?)`,
		name, description, string(blockCatsJSON), sp, sm)
	if err != nil {
		return 0, fmt.Errorf("insert group %q: %w", name, err)
	}

	return res.LastInsertId()
}

// UpdateGroup updates an existing client policy group.
func (d *DB) UpdateGroup(ctx context.Context, id int64, name, description string, blockCategories []string, strictPhishing, strictMalware bool) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	// Protect default group name
	if id == 1 {
		name = "default" // Force name to remain 'default' for protection
	}

	blockCatsJSON, err := json.Marshal(blockCategories)
	if err != nil {
		return fmt.Errorf("marshal block categories: %w", err)
	}

	sp := 0
	if strictPhishing {
		sp = 1
	}
	sm := 0
	if strictMalware {
		sm = 1
	}

	_, err = d.db.ExecContext(ctx, `
		UPDATE client_groups
		SET name = ?, description = ?, block_categories = ?, strict_phishing = ?, strict_malware = ?, updated_at = datetime('now')
		WHERE id = ?`,
		name, description, string(blockCatsJSON), sp, sm, id)
	if err != nil {
		return fmt.Errorf("update group id %d: %w", id, err)
	}

	return nil
}

// DeleteGroup deletes a client policy group.
func (d *DB) DeleteGroup(ctx context.Context, id int64) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	if id == 1 {
		return fmt.Errorf("cannot delete default policy group")
	}

	res, err := d.db.ExecContext(ctx, "DELETE FROM client_groups WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete group id %d: %w", id, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group not found: id %d", id)
	}

	return nil
}

// GetGroup retrieves a policy group by its ID.
func (d *DB) GetGroup(ctx context.Context, id int64) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRowContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups WHERE id = ?`, id).
		Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("%w: id %d", ErrGroupNotFound, id)
	}
	if err != nil {
		return nil, fmt.Errorf("get group id %d: %w", id, err)
	}

	_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
	g.StrictPhishing = sp != 0
	g.StrictMalware = sm != 0

	return &g, nil
}

// GetGroupByName retrieves a policy group by its unique name.
func (d *DB) GetGroupByName(ctx context.Context, name string) (*ClientGroup, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	var g ClientGroup
	var blockCatsJSON string
	var sp, sm int

	err := d.db.QueryRowContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups WHERE name = ?`, name).
		Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("group not found: name %s", name)
	}
	if err != nil {
		return nil, fmt.Errorf("get group name %s: %w", name, err)
	}

	_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
	g.StrictPhishing = sp != 0
	g.StrictMalware = sm != 0

	return &g, nil
}

// ListGroups returns all defined client policy groups.
func (d *DB) ListGroups(ctx context.Context) ([]ClientGroup, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT id, name, description, block_categories, strict_phishing, strict_malware, created_at, updated_at
		FROM client_groups ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var groups []ClientGroup
	for rows.Next() {
		var g ClientGroup
		var blockCatsJSON string
		var sp, sm int
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &blockCatsJSON, &sp, &sm, &g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		_ = json.Unmarshal([]byte(blockCatsJSON), &g.BlockCategories)
		g.StrictPhishing = sp != 0
		g.StrictMalware = sm != 0
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// AddMapping maps a client identifier (IP, CIDR, or DoH Client ID) to a policy group.
func (d *DB) AddMapping(ctx context.Context, mappingType, value, groupID string) (int64, error) {
	// Group ID is actually an integer, parse it
	var groupIDInt int64
	_, err := fmt.Sscanf(groupID, "%d", &groupIDInt)
	if err != nil {
		// Try parsing from database fallback or direct call helper
		return 0, fmt.Errorf("invalid group id: %w", err)
	}
	return d.AddMappingInt(ctx, mappingType, value, groupIDInt)
}

// AddMappingInt maps a client with group ID integer.
func (d *DB) AddMappingInt(ctx context.Context, mappingType, value string, groupID int64) (int64, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	mappingType = strings.TrimSpace(strings.ToLower(mappingType))
	if mappingType != "ip" && mappingType != "cidr" && mappingType != "client_id" {
		return 0, fmt.Errorf("invalid mapping type %q: must be 'ip', 'cidr', or 'client_id'", mappingType)
	}

	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("mapping value cannot be empty")
	}

	// Validate IP or CIDR formats
	switch mappingType {
	case "ip":
		if net.ParseIP(value) == nil {
			return 0, fmt.Errorf("invalid IP address format: %s", value)
		}
	case "cidr":
		_, ipNet, err := net.ParseCIDR(value)
		if err != nil {
			return 0, fmt.Errorf("invalid CIDR format %q: %w", value, err)
		}
		value = ipNet.String()
	}

	res, err := d.db.ExecContext(ctx, `
		INSERT INTO client_mappings (mapping_type, value, group_id)
		VALUES (?, ?, ?)`,
		mappingType, value, groupID)
	if err != nil {
		return 0, fmt.Errorf("insert mapping (%s, %s) -> group %d: %w", mappingType, value, groupID, err)
	}

	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	if mappingType == "cidr" {
		_ = d.loadCIDRCache()
	}

	return lastID, nil
}

// DeleteMapping removes a client device mapping.
func (d *DB) DeleteMapping(ctx context.Context, id int64) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	res, err := d.db.ExecContext(ctx, "DELETE FROM client_mappings WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("delete mapping id %d: %w", id, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("%w: id %d", ErrMappingNotFound, id)
	}

	_ = d.loadCIDRCache()
	return nil
}

// ListMappings returns all registered client mappings with group names.
func (d *DB) ListMappings(ctx context.Context) ([]ClientMapping, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT m.id, m.mapping_type, m.value, m.group_id, g.name, m.created_at
		FROM client_mappings m
		JOIN client_groups g ON m.group_id = g.id
		ORDER BY m.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var mappings []ClientMapping
	for rows.Next() {
		var m ClientMapping
		if err := rows.Scan(&m.ID, &m.MappingType, &m.Value, &m.GroupID, &m.GroupName, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan mapping: %w", err)
		}
		mappings = append(mappings, m)
	}
	return mappings, rows.Err()
}

// UpsertGroupOverride creates or updates a domain override rule specific to a policy group.
func (d *DB) UpsertGroupOverride(ctx context.Context, groupID int64, domain, action, reason string) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	if action != "allow" && action != "block" {
		return fmt.Errorf("invalid action %q: must be 'allow' or 'block'", action)
	}

	domain = strings.TrimSuffix(strings.TrimSpace(strings.ToLower(domain)), ".")
	if domain == "" {
		return fmt.Errorf("override domain cannot be empty")
	}
	// Same public-suffix rule as UpsertOverride: a group override is matched
	// against parents too, and a group override takes precedence over the
	// global one.
	if !analysis.IsRegistrableDomain(domain) {
		return fmt.Errorf("override domain %q is a public suffix or has no registrable label; use a domain you control such as example.com", domain)
	}

	_, err := d.db.ExecContext(ctx, `
		INSERT INTO group_overrides (group_id, domain, action, reason, updated_at)
		VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(group_id, domain) DO UPDATE SET
			action = excluded.action,
			reason = excluded.reason,
			updated_at = datetime('now')`,
		groupID, domain, action, reason)
	if err != nil {
		return fmt.Errorf("upsert group override (group %d, %s): %w", groupID, domain, err)
	}

	return nil
}

// DeleteGroupOverride removes a group-specific domain override.
func (d *DB) DeleteGroupOverride(ctx context.Context, groupID int64, domain string) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	res, err := d.db.ExecContext(ctx, "DELETE FROM group_overrides WHERE group_id = ? AND domain = ?", groupID, domain)
	if err != nil {
		return fmt.Errorf("delete group override (group %d, %s): %w", groupID, domain, err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("group override not found for group %d, domain %s", groupID, domain)
	}

	return nil
}

// ListGroupOverrides returns all override rules configured for a specific policy group.
func (d *DB) ListGroupOverrides(ctx context.Context, groupID int64) ([]GroupOverride, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT id, group_id, domain, action, reason, created_at, updated_at
		FROM group_overrides WHERE group_id = ?
		ORDER BY updated_at DESC`, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var overrides []GroupOverride
	for rows.Next() {
		var o GroupOverride
		if err := rows.Scan(&o.ID, &o.GroupID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan group override: %w", err)
		}
		overrides = append(overrides, o)
	}
	return overrides, rows.Err()
}

// GetGroupForClient dynamically resolves the policy group for a client request.
// It checks DoH ClientID mapping (only for authenticated identities), then exact
// IP, then CIDR ranges, and falls back to 'default'.
//
// clientIDTrusted must only be true when the caller has verified the client
// identity itself (mTLS client certificate, authenticated token, ...). A DoH
// client may freely choose its own client_id (query string or URL path), so an
// unverified client_id must never be allowed to select a policy group — policy
// then relies exclusively on the trusted client IP.
func (d *DB) GetGroupForClient(ctx context.Context, clientIP, clientID string, clientIDTrusted bool) (*ClientGroup, error) {
	if !d.Enabled() {
		return d.GetGroupByName(ctx, "default")
	}

	clientID = strings.TrimSpace(clientID)
	clientIP = strings.TrimSpace(clientIP)

	// 1. Check DoH Client ID mapping — authenticated identities only.
	if clientIDTrusted && clientID != "" {
		var groupID int64
		err := d.db.QueryRowContext(ctx,
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'client_id' AND value = ? LIMIT 1",
			clientID).Scan(&groupID)
		if err == nil {
			return d.GetGroup(ctx, groupID)
		}
	}

	// 2. Check exact IP mapping
	if clientIP != "" {
		var groupID int64
		err := d.db.QueryRowContext(ctx,
			"SELECT group_id FROM client_mappings WHERE mapping_type = 'ip' AND value = ? LIMIT 1",
			clientIP).Scan(&groupID)
		if err == nil {
			return d.GetGroup(ctx, groupID)
		}
	}

	// 3. Check CIDR mapping in high-performance RAM cache
	if clientIP != "" {
		ip := net.ParseIP(clientIP)
		if ip != nil {
			d.cidrMu.RLock()
			cache := d.cidrCache
			var matchedGroupID int64
			for _, entry := range cache {
				if entry.ipNet.Contains(ip) {
					matchedGroupID = entry.groupID
					break
				}
			}
			d.cidrMu.RUnlock()

			if matchedGroupID > 0 {
				return d.GetGroup(ctx, matchedGroupID)
			}
		}
	}

	// 4. Fallback to default group
	return d.GetGroupByName(ctx, "default")
}

// GetEffectiveOverride resolves allowed/blocked overrides specific to a policy group,
// falling back to Global local_overrides with intelligent subdomain inheritance.
//
// Deliberately the one store read that stays quiet when the store is disabled.
// Unlike the control-plane reads it sits on the DNS hot path, where its error
// feeds lookupEffectiveOverride — that logs and increments a counter on every
// failure, so returning ErrDisabled here would turn a local development run
// without a database into a warning per request. "No override is available" is
// both the correct and the quiet answer; genuine I/O failures still surface as
// errors and are still counted.
func (d *DB) GetEffectiveOverride(ctx context.Context, groupID int64, domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, nil
	}

	domain = strings.TrimSpace(strings.ToLower(domain))
	parts := strings.Split(domain, ".")

	// Traverse from specific to general, e.g. sub.example.com -> example.com,
	// but never past the registrable label (eTLD+1). Reaching "co.uk" or "com"
	// would let a row for a public suffix apply to an entire namespace, and
	// the decision pipeline consults overrides *before* the threat feed,
	// lexical scoring, ML, AI and OSINT, so an "allow" row there would disable
	// every one of those for all of .com.
	//
	// UpsertOverride rejects such rows, but a database written by an older
	// build can still contain them, so the lookup enforces the floor too.
	floor := analysis.RegistrableWalkFloor(domain)
	for i := 0; i < len(parts) && i <= floor; i++ {
		candidate := strings.Join(parts[i:], ".")

		// A. Check Group Override first (Group preference)
		var goid, ggroupID int64
		var gdomain, gaction, greason, gcreated, gupdated string
		err := d.db.QueryRowContext(ctx, `
			SELECT id, group_id, domain, action, reason, created_at, updated_at
			FROM group_overrides WHERE group_id = ? AND domain = ?`,
			groupID, candidate).
			Scan(&goid, &ggroupID, &gdomain, &gaction, &greason, &gcreated, &gupdated)
		if err == nil {
			return &Override{
				ID:        goid,
				Domain:    gdomain,
				Action:    gaction,
				Reason:    greason,
				CreatedAt: gcreated,
				UpdatedAt: gupdated,
			}, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("query group override candidate %s: %w", candidate, err)
		}

		// B. Check Global Override second (Global inheritance fallback)
		var o Override
		err = d.db.QueryRowContext(ctx, `
			SELECT id, domain, action, reason, created_at, updated_at
			FROM local_overrides WHERE domain = ?`, candidate).
			Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt)
		if err == nil {
			return &o, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("query global override candidate %s: %w", candidate, err)
		}
	}

	return nil, nil
}

func (d *DB) loadCIDRCache() error {
	if !d.Enabled() {
		return ErrDisabled
	}

	rows, err := d.db.QueryContext(context.Background(), "SELECT group_id, value FROM client_mappings WHERE mapping_type = 'cidr'")
	if err != nil {
		return err
	}
	defer func() { _ = rows.Close() }()

	var cache []cidrMapping
	for rows.Next() {
		var groupID int64
		var cidrVal string
		if err := rows.Scan(&groupID, &cidrVal); err == nil {
			_, ipNet, err := net.ParseCIDR(cidrVal)
			if err == nil {
				cache = append(cache, cidrMapping{
					groupID: groupID,
					ipNet:   ipNet,
				})
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	sort.Slice(cache, func(i, j int) bool {
		s1, _ := cache[i].ipNet.Mask.Size()
		s2, _ := cache[j].ipNet.Mask.Size()
		return s1 > s2
	})

	d.cidrMu.Lock()
	d.cidrCache = cache
	d.cidrMu.Unlock()
	return nil
}
