package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

// The threat-feed whitelist, its safety floor and its lookups live here.
// The sqlite.go breakup is complete: lifecycle/schema stay in sqlite.go;
// domains live in groups, telemetry, whitelist, reports, retention and
// overrides (same package, no API change).

// --- Whitelist ---

// UpdateWhitelist clears the existing whitelist and inserts a new set of domains
// in a single highly optimized transaction.
// ErrWhitelistBelowFloor reports an import that would leave the whitelist
// smaller than the configured floor allows. The live set is untouched, so the
// caller can retry, fall back, or raise an alert without having caused an
// outage by trying.
var ErrWhitelistBelowFloor = errors.New("whitelist import below safety floor")

const (
	// defaultWhitelistMinAbsolute is the floor used when the operator has not
	// set one. It is low enough to let a genuinely small whitelist through and
	// high enough to catch a download that produced nothing.
	defaultWhitelistMinAbsolute = 100
	// defaultWhitelistMinRelative is the percentage of the previous set that a
	// replacement must reach. 50 allows a legitimate halving while rejecting
	// the cliff-edge drops that a format change or a truncated body produce.
	defaultWhitelistMinRelative = 50
)

func (d *DB) whitelistMinAbsolute() int {
	value := config.Int("SAFE_ZONE_WHITELIST_MIN_ENTRIES", defaultWhitelistMinAbsolute)
	if value < 0 {
		return 0
	}
	return value
}

func (d *DB) whitelistMinRelative() int {
	value := config.Int("SAFE_ZONE_WHITELIST_MIN_PERCENT", defaultWhitelistMinRelative)
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

func (d *DB) UpdateWhitelist(ctx context.Context, domains []string) error {
	if !d.Enabled() {
		return ErrDisabled
	}

	// Entries that are a public suffix ("com", "co.uk", "github.io") are not
	// registrable domains, so they are never a legitimate entry. But the
	// runtime matches a whitelist entry against the domain *and its parents*,
	// so a stored "com" answers true for every .com domain and the request
	// comes back "whitelisted" — which short-circuits the threat feed, lexical
	// scoring, ML, AI, OSINT and group enforcement. One bad line in an
	// otherwise valid list silently disables protection for a whole namespace.
	//
	// The filter lives here rather than in the callers because this is the one
	// function every ingest path goes through: the operator's file import in
	// risk.Whitelist.LoadFromFile, and the agent's whitelist_update task,
	// which downloads from an operator-configured URL and previously wrote
	// straight to this method with no validation at all. Validating at the
	// storage boundary means a new caller cannot forget.
	//
	// risk.Whitelist.LoadFromFile also filters, so the count it logs is
	// unaffected: filtering an already-filtered list is a no-op.
	accepted := make([]string, 0, len(domains))
	dropped := 0
	for _, domain := range domains {
		if analysis.IsRegistrableDomain(domain) {
			accepted = append(accepted, domain)
			continue
		}
		dropped++
	}
	if dropped > 0 {
		logjson.Warn("dropped unsafe whitelist entries", map[string]any{
			"service":  "store",
			"dropped":  dropped,
			"accepted": len(accepted),
			"reason":   "entry is a public suffix or has no registrable label, and would allowlist every domain beneath it",
		})
	}

	// Poison floor.
	//
	// This table is a safety valve: a domain on it is reported SAFE and the
	// request never reaches the threat feed, lexical scoring, ML, AI, OSINT or
	// group enforcement. So wiping it is not a partial degradation, it is a
	// total loss of protection for every domain that was on it — which is
	// exactly what an empty or truncated download produces. A captive portal
	// page, a gzip bomb that unzips to nothing, an HTTP error body, or a
	// source that silently changes format all land here as "zero domains".
	//
	// The threat-feed path already refuses to replace a live set with zero
	// valid entries (feed.Sync); this is the same guard for the whitelist.
	//
	// It applies only when there is something to lose. An empty previous set
	// means the whitelist was not protecting anything, so a first import of any
	// size — including none — removes no protection and is accepted. That keeps
	// the floor out of the way of a small hand-written list while still
	// catching the cliff-edge drop that breaks a real deployment.
	//
	// Once populated, two conditions must hold: an absolute floor (a source
	// that held a million entries and now returns twelve is not a smaller
	// whitelist, it is a broken one) and a relative floor (so a legitimate
	// reshrink, such as the operator retiring a source, stays possible).
	//
	// A rejected import leaves the live set exactly as it was.
	previous, countErr := d.GetWhitelistCount(ctx)
	if countErr != nil {
		return fmt.Errorf("read current whitelist size before replace: %w", countErr)
	}
	if previous > 0 {
		minAbsolute := d.whitelistMinAbsolute()
		minRelative := d.whitelistMinRelative()
		if len(accepted) < minAbsolute {
			// Say why the number is low. The public-suffix filter runs first and
			// only records its drop count in a log line the caller cannot see, so
			// without this an operator reading the error sees "0 usable
			// entries" and has no way to tell an empty download from a source
			// that was entirely rejected as unsafe.
			reason := ""
			if dropped > 0 {
				reason = fmt.Sprintf(" (%d dropped: public suffix or no registrable label)", dropped)
			}
			return fmt.Errorf("%w: source returned %d usable entries%s, floor is %d; the live whitelist of %d entries is unchanged",
				ErrWhitelistBelowFloor, len(accepted), reason, minAbsolute, previous)
		}
		if len(accepted)*100 < previous*minRelative {
			return fmt.Errorf("%w: source returned %d entries, a drop from %d (floor is %d%%); the live whitelist is unchanged",
				ErrWhitelistBelowFloor, len(accepted), previous, minRelative)
		}
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin whitelist transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.ExecContext(ctx, "DELETE FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("delete old whitelist: %w", err)
	}

	for start := 0; start < len(accepted); start += whitelistInsertChunkSize {
		end := start + whitelistInsertChunkSize
		if end > len(accepted) {
			end = len(accepted)
		}

		query, args := buildWhitelistInsertQuery(accepted[start:end])
		if len(args) == 0 {
			continue
		}
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return fmt.Errorf("insert whitelist domains chunk [%d:%d]: %w", start, end, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit whitelist transaction: %w", err)
	}

	return nil
}

func buildWhitelistInsertQuery(domains []string) (string, []any) {
	args := make([]any, 0, len(domains))
	var builder strings.Builder
	builder.Grow(len("INSERT OR IGNORE INTO whitelist_domains (domain) VALUES ") + len(domains)*5)
	builder.WriteString("INSERT OR IGNORE INTO whitelist_domains (domain) VALUES ")

	for _, domain := range domains {
		if domain == "" {
			continue
		}
		if len(args) > 0 {
			builder.WriteString(",")
		}
		builder.WriteString("(?)")
		args = append(args, domain)
	}

	return builder.String(), args
}

// IsDomainWhitelisted checks if the domain exists exactly in the SQLite whitelist table.
func (d *DB) IsDomainWhitelisted(ctx context.Context, domain string) (bool, error) {
	if !d.Enabled() {
		return false, ErrDisabled
	}

	var exists int
	err := d.db.QueryRowContext(ctx, "SELECT 1 FROM whitelist_domains WHERE domain = ? LIMIT 1", domain).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check whitelist domain %s: %w", domain, err)
	}

	return true, nil
}

// GetWhitelistCount returns the number of domains stored in the SQLite whitelist table.
func (d *DB) GetWhitelistCount(ctx context.Context) (int, error) {
	if !d.Enabled() {
		return 0, ErrDisabled
	}

	var count int
	if err := d.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM whitelist_domains").Scan(&count); err != nil {
		return 0, fmt.Errorf("count whitelist domains: %w", err)
	}
	return count, nil
}

// StreamWhitelist iterates sequentially over whitelist domains without allocating
// an intermediate slice of all rows in memory.
func (d *DB) StreamWhitelist(ctx context.Context, fn func(string) error) error {
	if !d.Enabled() || fn == nil {
		return nil
	}

	rows, err := d.db.QueryContext(ctx, "SELECT domain FROM whitelist_domains")
	if err != nil {
		return fmt.Errorf("query whitelist domains: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return fmt.Errorf("scan whitelist domain: %w", err)
		}
		if err := fn(domain); err != nil {
			return fmt.Errorf("stream whitelist domain %s: %w", domain, err)
		}
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate whitelist domains: %w", err)
	}
	return nil
}

// GetWhitelist retrieves all domains in the SQLite whitelist table.
func (d *DB) GetWhitelist(ctx context.Context) ([]string, error) {
	if !d.Enabled() {
		return nil, ErrDisabled
	}

	rows, err := d.db.QueryContext(ctx, "SELECT domain FROM whitelist_domains")
	if err != nil {
		return nil, fmt.Errorf("query whitelist domains: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			return nil, fmt.Errorf("scan whitelist domain: %w", err)
		}
		domains = append(domains, domain)
	}

	return domains, rows.Err()
}
