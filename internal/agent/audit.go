package agent

import (
	"context"
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
}

// AuditTask scans the telemetry log for frequently-seen suspicious domains,
// enriches them with TLS/WHOIS/AI, and auto-blocks high-confidence malicious ones.
type AuditTask struct {
	store  *store.DB
	ai     *ai.Client
	redis  *cache.Redis
	config AuditConfig
	// lastAudit tracks the time window for suspicious domain queries.
	mu        sync.Mutex
	lastAudit time.Time
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
	return &AuditTask{
		store:     db,
		ai:        aiClient,
		redis:     redis,
		config:    cfg,
		lastAudit: time.Now().Add(-24 * time.Hour), // initial window: last 24h
	}
}

func (t *AuditTask) Name() string { return "audit" }

func (t *AuditTask) Run(ctx context.Context) error {
	if t.store == nil || !t.store.Enabled() {
		return nil
	}

	t.mu.Lock()
	since := t.lastAudit
	t.lastAudit = time.Now()
	t.mu.Unlock()

	domains, err := t.store.QuerySuspiciousDomains(context.Background(), since, t.config.MinOccurrences, t.config.MaxPerCycle)
	if err != nil {
		return fmt.Errorf("query suspicious domains: %w", err)
	}

	if len(domains) == 0 {
		return nil
	}

	result := AuditResult{}

	for _, dc := range domains {
		select {
		case <-ctx.Done():
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
			continue
		}

		switch action {
		case "blocked":
			result.AutoBlocked++
		case "skipped":
			result.Skipped++
		}
		result.Audited++
	}

	details := fmt.Sprintf(`{"audited":%d,"auto_blocked":%d,"skipped":%d,"errors":%d}`,
		result.Audited, result.AutoBlocked, result.Skipped, result.Errors)
	_ = t.store.RecordAgentEvent(context.Background(), "audit", "audit_completed", "", details)

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
	existing, err := t.store.GetOverride(context.Background(), domain)
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
		if err := t.store.UpsertOverride(context.Background(), domain, "block", reason); err != nil {
			return "", fmt.Errorf("upsert override: %w", err)
		}

		// Invalidate Redis cache for this domain.
		if t.redis != nil && t.redis.Enabled() {
			cacheKey := fmt.Sprintf("safe-zone:analysis:%s", domain)
			_ = t.redis.Delete(ctx, cacheKey)
		}

		details := fmt.Sprintf(`{"score":%d,"confidence":%.2f,"reasons":%q}`, score, confidence, reasons)
		_ = t.store.RecordAgentEvent(context.Background(), "audit", "auto_block", domain, details)

		return "blocked", nil
	}

	// Reviewed but no action.
	details := fmt.Sprintf(`{"score":%d,"confidence":%.2f,"verdict":"%s"}`, score, confidence, verdict)
	_ = t.store.RecordAgentEvent(context.Background(), "audit", "reviewed", domain, details)

	return "reviewed", nil
}
