package agent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// WhitelistUpdateConfig holds configuration for the Whitelist auto-update task.
type WhitelistUpdateConfig struct {
	SourceURL string
	Timeout   time.Duration
	Enabled   bool
	// MaxDownloadBytes caps the source response buffered in memory before
	// parsing. Zero means DefaultWhitelistDownloadBytes. The parse stage
	// keeps its own 128MiB reader cap; this one guards the buffer.
	MaxDownloadBytes int64
	// AllowPrivateSources permits fetching from private/test hosts.
	// Default false: the updater is a scheduled background task, so its
	// egress must pass the shared outbound policy like every other
	// collector. Tests opt in for loopback fixtures.
	AllowPrivateSources bool
	// SHA256 is the expected digest of the downloaded source file, in hex.
	// When set, a body that does not match is rejected before it is parsed,
	// so a truncated download or a tampered response cannot replace the
	// allow list. Empty skips the check, which is only acceptable for a
	// source the operator controls end to end.
	SHA256 string
}

// DefaultWhitelistDownloadBytes bounds the whitelist source download.
// Tranco top-1M CSVs are tens of megabytes; 64MiB leaves headroom without
// letting a runaway response exhaust a small VPS.
const DefaultWhitelistDownloadBytes = 64 << 20

// WhitelistUpdateTask implements the agent.Task interface to update the clean list.
type WhitelistUpdateTask struct {
	store     *store.DB
	whitelist *risk.Whitelist
	config    WhitelistUpdateConfig
}

// NewWhitelistUpdateTask creates a new WhitelistUpdateTask.
func NewWhitelistUpdateTask(db *store.DB, wl *risk.Whitelist, cfg WhitelistUpdateConfig) *WhitelistUpdateTask {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute // 1 million entries can take a moment to download and import
	}
	if cfg.MaxDownloadBytes <= 0 {
		cfg.MaxDownloadBytes = DefaultWhitelistDownloadBytes
	}
	return &WhitelistUpdateTask{
		store:     db,
		whitelist: wl,
		config:    cfg,
	}
}

// Name returns the unique task name.
func (t *WhitelistUpdateTask) Name() string {
	return "whitelist_update"
}

// Run executes the task.
func (t *WhitelistUpdateTask) Run(ctx context.Context) error {
	if !t.config.Enabled {
		return nil
	}
	if t.store == nil || !t.store.Enabled() {
		return fmt.Errorf("sqlite store is disabled or nil, cannot run whitelist update task")
	}
	if t.config.SourceURL == "" {
		return fmt.Errorf("whitelist update source URL is empty")
	}

	logjson.Info("agent whitelist update started", correlation.Fields(ctx, map[string]any{
		"service": "core-api",
		"task":    "whitelist_update",
		"source":  t.config.SourceURL,
	}))
	_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_started", "", "Download and import started")

	start := time.Now()
	domains, err := t.downloadAndParse(ctx)
	if err != nil {
		logjson.Error("agent whitelist update failed", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"source":  t.config.SourceURL,
			"error":   err.Error(),
		}))
		details := fmt.Sprintf(`{"error":%q}`, err.Error())
		_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_failed", "", details)
		return err
	}

	logjson.Info("agent whitelist update parsed", correlation.Fields(ctx, map[string]any{
		"service": "core-api",
		"task":    "whitelist_update",
		"domains": len(domains),
	}))

	// Update SQLite. A rollback copy of the live allow list is taken first:
	// the import replaces the whole set, and the allow list is the primary
	// safety valve, so an import that goes wrong must be undoable.
	snapshotID, err := t.snapshotCurrentAllowList(ctx)
	if err != nil {
		logjson.Error("agent whitelist update could not snapshot the allow list", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"error":   err.Error(),
		}))
		details := fmt.Sprintf(`{"error":%q}`, err.Error())
		_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_failed", "", details)
		return fmt.Errorf("snapshot allow list: %w", err)
	}

	if err := t.store.UpdateWhitelist(ctx, domains); err != nil {
		logjson.Error("agent whitelist update sqlite write failed", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"domains": len(domains),
			"error":   err.Error(),
		}))
		details := fmt.Sprintf(`{"error":%q}`, err.Error())
		_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_failed", "", details)
		return fmt.Errorf("update sqlite: %w", err)
	}

	// Reload RAM Bloom Filter
	logjson.Info("agent whitelist update rebuilding bloom filter", correlation.Fields(ctx, map[string]any{
		"service": "core-api",
		"task":    "whitelist_update",
		"domains": len(domains),
	}))
	if err := t.whitelist.LoadFromDB(); err != nil {
		logjson.Error("agent whitelist update bloom rebuild failed", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"domains": len(domains),
			"error":   err.Error(),
		}))
		details := fmt.Sprintf(`{"error":%q}`, err.Error())
		_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_failed", "", details)
		// The durable set was replaced but the RAM index was not rebuilt, so
		// the two disagree. Put the previous set back.
		t.restoreSnapshot(ctx, snapshotID)
		return fmt.Errorf("reload bloom filter: %w", err)
	}

	elapsed := time.Since(start)
	stats := map[string]any{
		"domains_count": len(domains),
		"elapsed_ms":    elapsed.Milliseconds(),
	}
	statsJSON, _ := json.Marshal(stats)
	_ = t.store.RecordAgentEvent(context.Background(), "whitelist_update", "whitelist_update_completed", "", string(statsJSON))

	logjson.Info("agent whitelist update completed", correlation.Fields(ctx, map[string]any{
		"service":     "core-api",
		"task":        "whitelist_update",
		"domains":     len(domains),
		"duration_ms": elapsed.Milliseconds(),
	}))
	return nil
}

// verifyChecksum compares the downloaded body against the expected digest.
//
// The allow list is the primary safety valve, so a body that is not the file
// the operator expects must never be parsed and imported. A truncated
// download, a captive-portal page or a tampered response all reach the
// import path as "a valid list of domains" unless something checks them.
func (t *WhitelistUpdateTask) verifyChecksum(body []byte) error {
	expected := strings.ToLower(strings.TrimSpace(t.config.SHA256))
	if expected == "" {
		logjson.Warn("agent whitelist update has no expected checksum; the download is trusted as-is", correlation.Fields(context.Background(), map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"source":  t.config.SourceURL,
			"remedy":  "set SAFE_ZONE_AGENT_WHITELIST_SHA256 to the digest of the expected file",
		}))
		return nil
	}

	sum := sha256.Sum256(body)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("whitelist source checksum mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

// snapshotCurrentAllowList stores a rollback copy of the live allow list
// before it is replaced.
func (t *WhitelistUpdateTask) snapshotCurrentAllowList(ctx context.Context) (int64, error) {
	var domains []string
	if err := t.store.StreamWhitelist(ctx, func(domain string) error {
		domains = append(domains, domain)
		return nil
	}); err != nil {
		return 0, fmt.Errorf("read current whitelist for snapshot: %w", err)
	}
	if len(domains) == 0 {
		// Nothing to lose: the first import has no previous set to restore.
		return 0, nil
	}

	id, err := t.store.SaveWhitelistSnapshot(ctx, t.config.SourceURL, domains)
	if err != nil {
		return 0, fmt.Errorf("save whitelist snapshot: %w", err)
	}
	logjson.Info("agent whitelist update saved a rollback snapshot", correlation.Fields(ctx, map[string]any{
		"service":  "core-api",
		"task":     "whitelist_update",
		"snapshot": id,
		"entries":  len(domains),
	}))
	return id, nil
}

// restoreSnapshot puts the allow list back after a failed import.
func (t *WhitelistUpdateTask) restoreSnapshot(ctx context.Context, id int64) {
	if id == 0 {
		return
	}
	if _, err := t.store.RestoreWhitelistSnapshot(ctx, id); err != nil {
		logjson.Error("agent whitelist update could not restore the rollback snapshot", correlation.Fields(ctx, map[string]any{
			"service":  "core-api",
			"task":     "whitelist_update",
			"snapshot": id,
			"error":    err.Error(),
		}))
		return
	}
	if err := t.whitelist.LoadFromDB(); err != nil {
		logjson.Error("agent whitelist update could not rebuild the index after the rollback", correlation.Fields(ctx, map[string]any{
			"service":  "core-api",
			"task":     "whitelist_update",
			"snapshot": id,
			"error":    err.Error(),
		}))
		return
	}
	logjson.Info("agent whitelist update restored the rollback snapshot", correlation.Fields(ctx, map[string]any{
		"service":  "core-api",
		"task":     "whitelist_update",
		"snapshot": id,
	}))
}

func (t *WhitelistUpdateTask) downloadAndParse(ctx context.Context) ([]string, error) {
	if _, err := netguard.ValidateURL(t.config.SourceURL, t.config.AllowPrivateSources); err != nil {
		return nil, fmt.Errorf("validate whitelist source: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", t.config.SourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	client := netguard.NewHTTPClient(nil, t.config.Timeout, t.config.AllowPrivateSources)
	client.CheckRedirect = netguard.RedirectPolicy(t.config.AllowPrivateSources)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error: status code %d", resp.StatusCode)
	}

	// Read the body bounded: zip needs random access so bytes must be
	// buffered, but an unbounded copy lets a runaway response exhaust
	// memory before the parse-stage cap ever applies.
	limit := t.config.MaxDownloadBytes
	if limit <= 0 {
		limit = DefaultWhitelistDownloadBytes
	}
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(resp.Body, limit+1)); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if int64(buf.Len()) > limit {
		return nil, fmt.Errorf("whitelist source exceeds %d bytes download cap", limit)
	}

	if err := t.verifyChecksum(buf.Bytes()); err != nil {
		return nil, err
	}

	zipReader, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		// Fallback: If it's not a ZIP, check if it's a raw CSV file
		logjson.Warn("agent whitelist update zip parse failed, trying raw csv fallback", correlation.Fields(ctx, map[string]any{
			"service": "core-api",
			"task":    "whitelist_update",
			"source":  t.config.SourceURL,
		}))
		return t.parseCSV(bytes.NewReader(buf.Bytes()))
	}

	// Iterate files in the ZIP to find the CSV
	var csvFile *zip.File
	for _, f := range zipReader.File {
		if strings.HasSuffix(strings.ToLower(f.Name), ".csv") {
			csvFile = f
			break
		}
	}

	if csvFile == nil {
		// If no CSV file is found, fallback to the first file in the ZIP
		if len(zipReader.File) > 0 {
			csvFile = zipReader.File[0]
		} else {
			return nil, fmt.Errorf("no files found inside ZIP archive")
		}
	}

	rc, err := csvFile.Open()
	if err != nil {
		return nil, fmt.Errorf("open file inside zip: %w", err)
	}
	defer func() { _ = rc.Close() }()

	return t.parseCSV(rc)
}

func (t *WhitelistUpdateTask) parseCSV(r io.Reader) ([]string, error) {
	var domains []string
	bufReader := io.LimitReader(r, 128*1024*1024) // absolute safety limit: 128MB max

	scanner := bufio.NewScanner(bufReader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ",")
		domain := parts[0]
		if len(parts) >= 2 {
			domain = parts[1] // typical "rank,domain" format
		}

		normalized, err := analysis.NormalizeDomain(domain)
		if err == nil && normalized != "" {
			domains = append(domains, normalized)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan csv: %w", err)
	}

	return domains, nil
}
