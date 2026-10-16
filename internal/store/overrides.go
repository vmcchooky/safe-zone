package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"safe-zone/internal/analysis"
)

// Global domain allow/block overrides (local_overrides table) live here.
// The sqlite.go breakup is complete: lifecycle/schema stay in sqlite.go; domains live
// in groups, telemetry, whitelist, reports, retention and overrides.

// --- Overrides ---

// GetOverride checks if a domain (or any of its parent domains) has an override.
// Returns nil if no override is found.
func (d *DB) GetOverride(ctx context.Context, domain string) (*Override, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}
	// Check the exact match and its parents, stopping at the registrable
	// label (eTLD+1). A row keyed on a public suffix would otherwise apply to
	// every domain in that namespace, and this function is reached from the
	// agent's audit path, so a legacy "com" row would make the agent treat
	// every .com domain as already having an override. UpsertOverride refuses
	// such rows; the floor here covers databases written by older builds.
	parts := strings.Split(domain, ".")
	floor := analysis.RegistrableWalkFloor(domain)
	for i := 0; i < len(parts) && i <= floor; i++ {
		candidate := strings.Join(parts[i:], ".")
		var o Override
		err := d.db.QueryRowContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides WHERE domain = ?`, candidate).
			Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt)
		if err == nil {
			return &o, nil
		}
		if err != sql.ErrNoRows {
			return nil, fmt.Errorf("get override %s: %w", candidate, err)
		}
	}
	return nil, nil
}

// ListOverrides returns all overrides, optionally filtered by action.
func (d *DB) ListOverrides(ctx context.Context, action string) ([]Override, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	var rows *sql.Rows
	var err error
	if action == "allow" || action == "block" {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides WHERE action = ? ORDER BY updated_at DESC`, action)
	} else {
		rows, err = d.db.QueryContext(ctx,
			`SELECT id, domain, action, reason, created_at, updated_at
			 FROM local_overrides ORDER BY updated_at DESC`)
	}
	if err != nil {
		return nil, fmt.Errorf("list overrides: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var overrides []Override
	for rows.Next() {
		var o Override
		if err := rows.Scan(&o.ID, &o.Domain, &o.Action, &o.Reason, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan override: %w", err)
		}
		overrides = append(overrides, o)
	}
	return overrides, rows.Err()
}

// UpsertOverride creates or updates an override for a domain.
func (d *DB) UpsertOverride(ctx context.Context, domain, action, reason string) error {
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
	// An override row is matched against the domain and its parents, so a
	// public suffix would apply to the whole namespace: an "allow" for "com"
	// would short-circuit the threat feed, lexical scoring, ML, AI and OSINT
	// for every .com domain, and a "block" would take all of .com offline.
	if !analysis.IsRegistrableDomain(domain) {
		return fmt.Errorf("override domain %q is a public suffix or has no registrable label; use a domain you control such as example.com", domain)
	}
	_, err := d.db.ExecContext(ctx, `
		INSERT INTO local_overrides (domain, action, reason, updated_at)
		VALUES (?, ?, ?, datetime('now'))
		ON CONFLICT(domain) DO UPDATE SET
			action = excluded.action,
			reason = excluded.reason,
			updated_at = datetime('now')`,
		domain, action, reason)
	if err != nil {
		return fmt.Errorf("upsert override %s: %w", domain, err)
	}
	return nil
}

// DeleteOverride removes an override for a domain.
func (d *DB) DeleteOverride(ctx context.Context, domain string) error {
	if !d.Enabled() {
		return ErrDisabled
	}
	result, err := d.db.ExecContext(ctx, `DELETE FROM local_overrides WHERE domain = ?`, domain)
	if err != nil {
		return fmt.Errorf("delete override %s: %w", domain, err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return fmt.Errorf("override not found: %s", domain)
	}
	return nil
}
