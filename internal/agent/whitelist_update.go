package agent

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/risk"
	"safe-zone/internal/store"
)

// WhitelistUpdateConfig holds configuration for the Whitelist auto-update task.
type WhitelistUpdateConfig struct {
	SourceURL string
	Timeout   time.Duration
	Enabled   bool
}

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

	// Update SQLite
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

func (t *WhitelistUpdateTask) downloadAndParse(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", t.config.SourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	client := &http.Client{
		Timeout: t.config.Timeout,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http error: status code %d", resp.StatusCode)
	}

	// Read everything into memory. Zip requires random access, so we must buffer the bytes.
	var buf bytes.Buffer
	_, err = io.Copy(&buf, resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
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
	defer rc.Close()

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
