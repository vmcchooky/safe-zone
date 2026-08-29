package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"safe-zone/internal/ai"
	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// AuditConfig holds configuration for the Telemetry Audit Task.
type AuditConfig struct {
	MinOccurrences      int
	MaxPerCycle         int
	ConfidenceThreshold float64
	EnrichTimeout       time.Duration
	// Lookback is the audit window length. Each cycle pages through a frozen
	// [windowEnd-Lookback, windowEnd) window; a window is only retired once
	// every domain in it has been processed.
	Lookback time.Duration
}

// auditCursorState is the persisted audit position. windowEnd is the frozen
// exclusive upper bound of the current window; lastDomain is the keyset
// resume point inside that window. Version guards future schema changes.
type auditCursorState struct {
	Version    int    `json:"version"`
	WindowEnd  string `json:"window_end"`
	LastDomain string `json:"last_domain,omitempty"`
}

const (
	auditCursorVersion     = 1
	auditCursorConfigKey   = "agent_audit_cursor"
	defaultAuditMaxPerTime = 24 * time.Hour
)

// AuditTask scans the telemetry log for frequently-seen suspicious domains,
// enriches them with TLS/WHOIS/AI, and auto-blocks high-confidence malicious ones.
type AuditTask struct {
	store  *store.DB
	ai     *ai.Client
	redis  *cache.Redis
	config AuditConfig
	// cursor is thread-safe and survives restarts via the system_config
	// table; a failed persistence is logged and degrades to at-least-once
	// reprocessing instead of data loss.
	mu     sync.Mutex
	cursor auditCursorState
}

// AuditResult summarizes one audit cycle.
type AuditResult struct {
	Audited     int `json:"audited"`
	AutoBlocked int `json:"auto_blocked"`
	Skipped     int `json:"skipped"`
	Errors      int `json:"errors"`
}

// NewAuditTask creates an AuditTask with the given dependencies.
func NewAuditTask(db *store.DB, aiClient *ai.Client, redis *cache.Redis, cfg AuditConfig) *AuditTask {
	if cfg.MinOccurrences <= 0 {
		cfg.MinOccurrences = 3
	}
	if cfg.MaxPerCycle <= 0 {
		cfg.MaxPerCycle = 50
	}
	if cfg.ConfidenceThreshold <= 0 {
		cfg.ConfidenceThreshold = 0.7
	}
	if cfg.EnrichTimeout <= 0 {
		cfg.EnrichTimeout = 5 * time.Second
	}
	if cfg.Lookback <= 0 {
		cfg.Lookback = defaultAuditMaxPerTime
	}
	task := &AuditTask{
		store:  db,
		ai:     aiClient,
		redis:  redis,
		config: cfg,
		cursor: auditCursorState{Version: auditCursorVersion},
	}
	if db != nil && db.Enabled() {
		task.loadCursor(context.Background())
	}
	return task
}

func (t *AuditTask) Name() string { return "audit" }

// loadCursor restores the persisted audit position. Any failure falls back to
// a fresh window, which can re-audit domains (idempotent) but never skips one.
func (t *AuditTask) loadCursor(ctx context.Context) {
	raw, err := t.store.GetSystemConfig(ctx, auditCursorConfigKey)
	if err != nil {
		logjson.Warn("audit cursor load failed; starting a fresh window", map[string]any{
			"service": "core-api",
			"task":    "audit",
			"error":   err.Error(),
		})
		return
	}
	if raw == "" {
		return
	}
	var cursor auditCursorState
	if err := json.Unmarshal([]byte(raw), &cursor); err != nil || cursor.Version != auditCursorVersion || cursor.WindowEnd == "" {
		logjson.Warn("audit cursor unreadable; starting a fresh window", map[string]any{
			"service": "core-api",
			"task":    "audit",
		})
		return
	}
	if _, err := time.Parse(time.RFC3339Nano, cursor.WindowEnd); err != nil {
		logjson.Warn("audit cursor window end unreadable; starting a fresh window", map[string]any{
			"service": "core-api",
			"task":    "audit",
		})
		return
	}
	t.cursor = cursor
}

func (t *AuditTask) snapshotCursor() auditCursorState {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cursor
}

// auditCursorPersistTimeout bounds the detached write used to persist the
// cursor when the task context is already cancelled.
const auditCursorPersistTimeout = 2 * time.Second

// testHookAfterDomain is a deterministic test seam invoked after each
// successfully audited domain; it is nil in production.
var testHookAfterDomain func()

func (t *AuditTask) storeCursor(ctx context.Context, cursor auditCursorState) {
	t.mu.Lock()
	t.cursor = cursor
	t.mu.Unlock()

	if t.store == nil || !t.store.Enabled() {
		return
	}
	encoded, err := json.Marshal(cursor)
	if err != nil {
		logjson.Warn("audit cursor encode failed; restart may re-audit a page", map[string]any{
			"service": "core-api",
			"task":    "audit",
			"error":   err.Error(),
		})
		return
	}
	// The cursor must survive a cancelled task context (mid-page
	// cancellation commits the processed prefix), so the write runs on a
	// detached but strictly bounded context instead of the caller's.
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditCursorPersistTimeout)
	defer cancel()
	if err := t.store.SetSystemConfig(persistCtx, auditCursorConfigKey, string(encoded)); err != nil {
		logjson.Warn("audit cursor persist failed; restart may re-audit a page", map[string]any{
			"service": "core-api",
			"task":    "audit",
			"error":   err.Error(),
		})
	}
}

func (t *AuditTask) Run(ctx context.Context) error {
	if t.store == nil || !t.store.Enabled() {
		return nil
	}

	cursor := t.snapshotCursor()
	windowEnd := time.Time{}
	if cursor.WindowEnd != "" {
		parsed, err := time.Parse(time.RFC3339Nano, cursor.WindowEnd)
		if err != nil {
			return fmt.Errorf("audit cursor window end: %w", err)
		}
		windowEnd = parsed
	}
	if windowEnd.IsZero() {
		windowEnd = time.Now()
		cursor.WindowEnd = windowEnd.UTC().Format(time.RFC3339Nano)
	} else if cursor.LastDomain == "" && windowEnd.Before(time.Now().Add(-t.config.Lookback)) {
		// A completed window whose end precedes any data we still keep: start
		// a new one. A mid-window cursor (last_domain set) is never reset —
		// resuming a frozen window is what prevents skipped domains.
		windowEnd = time.Now()
		cursor.WindowEnd = windowEnd.UTC().Format(time.RFC3339Nano)
	}
	windowStart := windowEnd.Add(-t.config.Lookback)

	domains, err := t.store.QuerySuspiciousDomainsPage(ctx, windowStart, windowEnd, t.config.MinOccurrences, t.config.MaxPerCycle, cursor.LastDomain)
	if err != nil {
		// Cursor stays put: the window is retried on the next cycle.
		return fmt.Errorf("query suspicious domains page: %w", err)
	}

	if len(domains) == 0 {
		// Window exhausted: retire it and start a new one on the next cycle.
		t.storeCursor(ctx, auditCursorState{Version: auditCursorVersion, WindowEnd: time.Now().UTC().Format(time.RFC3339Nano)})
		return nil
	}

	result := AuditResult{}
	lastDone := ""
	for _, dc := range domains {
		select {
		case <-ctx.Done():
			if lastDone != "" {
				// Commit the successfully audited prefix of this page so a
				// cancellation does not repeat it.
				t.storeCursor(ctx, auditCursorState{Version: auditCursorVersion, WindowEnd: cursor.WindowEnd, LastDomain: lastDone})
			}
			return ctx.Err()
		default:
		}

		action, err := t.auditDomain(ctx, dc.Domain)
		if err != nil {
			logjson.Error("agent audit domain error", correlation.Fields(ctx, map[string]any{
				"service": "core-api",
				"task":    "audit",
				"domain":  dc.Domain,
				"error":   err.Error(),
			}))
			result.Errors++
			// Stop the page at the failure and keep the cursor retryable so
			// this domain and the rest of the page are never skipped.
			if lastDone != "" {
				t.storeCursor(ctx, auditCursorState{Version: auditCursorVersion, WindowEnd: cursor.WindowEnd, LastDomain: lastDone})
			}
			return fmt.Errorf("audit domain %s: %w", dc.Domain, err)
		}

		switch action {
		case "blocked":
			result.AutoBlocked++
		case "skipped":
			result.Skipped++
		}
		result.Audited++
		lastDone = dc.Domain
		if testHookAfterDomain != nil {
			testHookAfterDomain()
		}
	}

	if len(domains) < t.config.MaxPerCycle {
		// Page exhausted the window: retire it. The new window starts where
		// this one ended, so no domain is skipped.
		t.storeCursor(ctx, auditCursorState{Version: auditCursorVersion, WindowEnd: time.Now().UTC().Format(time.RFC3339Nano)})
	} else {
		// More domains remain in the frozen window: resume there next cycle.
		t.storeCursor(ctx, auditCursorState{Version: auditCursorVersion, WindowEnd: cursor.WindowEnd, LastDomain: lastDone})
	}

	details := fmt.Sprintf(`{"audited":%d,"auto_blocked":%d,"skipped":%d,"errors":%d}`,
		result.Audited, result.AutoBlocked, result.Skipped, result.Errors)
	_ = t.store.RecordAgentEvent(ctx, "audit", "audit_completed", "", details)

	logjson.Info("agent audit completed", correlation.Fields(ctx, map[string]any{
		"service":      "core-api",
		"task":         "audit",
		"audited":      result.Audited,
		"auto_blocked": result.AutoBlocked,
		"skipped":      result.Skipped,
		"errors":       result.Errors,
	}))

	return nil
}

// auditDomain enriches a single domain and decides whether to auto-block.
// Returns "blocked", "skipped", or "reviewed".
func (t *AuditTask) auditDomain(ctx context.Context, domain string) (string, error) {
	// Skip if domain already has an override (respect admin intent).
	existing, err := t.store.GetOverride(ctx, domain)
	if err != nil {
		return "", fmt.Errorf("check override: %w", err)
	}
	if existing != nil {
		return "skipped", nil
	}

	// Run TLS + WHOIS enrichment in parallel.
	enrichCtx, cancel := context.WithTimeout(ctx, t.config.EnrichTimeout)
	defer cancel()

	var (
		tlsResult   tlsinspect.Result
		whoisResult whois.Result
		wg          sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		tlsResult = tlsinspect.Inspect(enrichCtx, domain)
	}()
	go func() {
		defer wg.Done()
		whoisResult = whois.Lookup(enrichCtx, domain)
	}()
	wg.Wait()

	// Build a merged score from enrichment signals.
	score := tlsResult.Score + whoisResult.Score
	var reasons []string
	reasons = append(reasons, tlsResult.Reasons...)
	reasons = append(reasons, whoisResult.Reasons...)

	// Determine interim verdict.
	verdict := analysis.VerdictSuspicious
	if score >= 70 {
		verdict = analysis.VerdictMalicious
	} else if score < 40 {
		verdict = analysis.VerdictSafe
	}

	confidence := 0.45 + float64(score)/120
	if confidence > 1 {
		confidence = 1
	}

	// Optional AI refinement for ambiguous cases.
	if t.ai != nil && t.ai.Enabled() && verdict == analysis.VerdictSuspicious {
		current := analysis.Result{
			Domain:     domain,
			Verdict:    verdict,
			Score:      score,
			Confidence: confidence,
			Reasons:    reasons,
		}
		aiResult, aiErr := t.ai.Refine(ctx, domain, current)
		if aiErr == nil && aiResult.Verdict == analysis.VerdictMalicious {
			verdict = analysis.VerdictMalicious
			if aiResult.Score > score {
				score = aiResult.Score
			}
			if aiResult.Confidence > confidence {
				confidence = aiResult.Confidence
			}
			reasons = append(reasons, aiResult.Reasons...)
		}
	}

	// Cap score.
	if score > 100 {
		score = 100
	}

	// Decision: auto-block if malicious with high confidence.
	if verdict == analysis.VerdictMalicious && confidence >= t.config.ConfidenceThreshold {
		reason := fmt.Sprintf("agent: auto-block (enriched, score=%d, confidence=%.2f)", score, confidence)
		if err := t.store.UpsertOverride(ctx, domain, "block", reason); err != nil {
			return "", fmt.Errorf("upsert override: %w", err)
		}

		// Invalidate the cached analysis for exactly this domain (base key
		// plus model-revision variants). A failure is logged: a stale cached
		// verdict would shadow the block anywhere the cache is read.
		cacheInvalidated := "ok"
		if err := invalidateAnalysisCache(ctx, t.redis, domain); err != nil && ctx.Err() == nil {
			cacheInvalidated = "failed"
			logjson.Warn("agent analysis cache invalidation failed", correlation.Fields(ctx, map[string]any{
				"service": "core-api",
				"task":    "audit",
				"domain":  domain,
				"error":   err.Error(),
			}))
		}

		details, err := json.Marshal(map[string]any{
			"score":              score,
			"confidence":         confidence,
			"reasons":            reasons,
			"cache_invalidation": cacheInvalidated,
		})
		if err == nil {
			_ = t.store.RecordAgentEvent(ctx, "audit", "auto_block", domain, string(details))
		} else {
			_ = t.store.RecordAgentEvent(ctx, "audit", "auto_block", domain,
				fmt.Sprintf(`{"score":%d,"confidence":%.2f,"cache_invalidation":%q}`, score, confidence, cacheInvalidated))
		}

		return "blocked", nil
	}

	// Reviewed but no action.
	details := fmt.Sprintf(`{"score":%d,"confidence":%.2f,"verdict":%q}`, score, confidence, verdict)
	_ = t.store.RecordAgentEvent(ctx, "audit", "reviewed", domain, details)

	return "reviewed", nil
}
