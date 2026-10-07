package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/cache"
)

const (
	ProductionFreePreset           = "production-free"
	ProductionVNPreset             = "production-vn"
	defaultStaleAfter              = 36 * time.Hour
	defaultParserDriftInvalidRatio = 0.20
	defaultParserDriftMinInvalid   = 25
	defaultCacheInvalidationWrites = int64(1)
)

var productionFreeSources = []string{
	"https://urlhaus.abuse.ch/downloads/csv_recent/",
	"https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
}

var productionVNSources = []string{
	"https://urlhaus.abuse.ch/downloads/csv_recent/",
	"https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt",
	"https://raw.githubusercontent.com/phishdestroy/destroylist/main/rootlist/formats/primary_active/domains.txt",
	"https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
}

type SourceStatus struct {
	Source            string     `json:"source"`
	SourceID          string     `json:"source_id"`
	FeedKey           string     `json:"feed_key"`
	Status            string     `json:"status"`
	LastAttemptAt     string     `json:"last_attempt_at,omitempty"`
	LastSuccessAt     string     `json:"last_success_at,omitempty"`
	LastFailureAt     string     `json:"last_failure_at,omitempty"`
	LastError         string     `json:"last_error,omitempty"`
	Stats             ParseStats `json:"stats"`
	Written           int64      `json:"written"`
	Replace           bool       `json:"replace"`
	FinishedAt        string     `json:"finished_at,omitempty"`
	ParserDrift       bool       `json:"parser_drift"`
	ParserDriftReason string     `json:"parser_drift_reason,omitempty"`
	// EmptyIngest marks a successful sync that produced zero valid domains.
	//
	// This is the additive-path counterpart to the Replace guard that refuses to
	// wipe the live feed on an empty parse. In additive mode nothing is wiped, so
	// there was nothing to refuse: the sync exited 0, recorded success, and the
	// source's members simply aged out over their TTL, weakening blocking with no
	// signal at all. ParserDrift cannot cover it, because an empty or
	// comment-only body has no invalid lines, so the invalid-ratio denominator is
	// zero and drift reports false.
	//
	// It is deliberately separate from ParserDrift rather than folded into it:
	// the two have different causes and need different operator responses.
	EmptyIngest       bool            `json:"empty_ingest"`
	EmptyIngestReason string          `json:"empty_ingest_reason,omitempty"`
	CacheInvalidated  bool            `json:"cache_invalidated"`
	FeedRevision      int64           `json:"feed_revision,omitempty"`
	Admission         *AdmissionStats `json:"admission,omitempty"`
	Shadow            *ShadowDiff     `json:"shadow,omitempty"`
	Stale             bool            `json:"stale"`
}

type StatusSummary struct {
	Configured    bool   `json:"configured"`
	Preset        string `json:"preset,omitempty"`
	FeedKey       string `json:"feed_key,omitempty"`
	Status        string `json:"status"`
	Error         string `json:"error,omitempty"`
	ActiveEntries int64  `json:"active_entries"`
	Stale         bool   `json:"stale"`
	ParserDrift   bool   `json:"parser_drift"`
	// EmptyIngest is true when any configured source synced successfully but
	// yielded zero valid domains. It reaches alerting through the per-source flag
	// rather than through Status, so an operator sees which source emptied out.
	EmptyIngest   bool           `json:"empty_ingest"`
	Revision      int64          `json:"revision,omitempty"`
	LastAttemptAt string         `json:"last_attempt_at,omitempty"`
	LastSuccessAt string         `json:"last_success_at,omitempty"`
	StaleAfter    string         `json:"stale_after,omitempty"`
	Sources       []SourceStatus `json:"sources,omitempty"`
}

func ParseSources(raw string) []string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r'
	})
	if len(parts) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(parts))
	sources := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, exists := seen[part]; exists {
			continue
		}
		seen[part] = struct{}{}
		sources = append(sources, part)
	}
	return sources
}

func ResolveSources(rawSources string, preset string) ([]string, error) {
	if sources := ParseSources(rawSources); len(sources) > 0 {
		return sources, nil
	}

	switch strings.ToLower(strings.TrimSpace(preset)) {
	case "":
		return nil, nil
	case ProductionFreePreset:
		return ProductionFreeSources(), nil
	case ProductionVNPreset:
		return ProductionVNSources(), nil
	default:
		return nil, fmt.Errorf("unknown threat feed preset %q", preset)
	}
}

func ProductionVNSources() []string {
	out := make([]string, len(productionVNSources))
	copy(out, productionVNSources)
	return out
}

func ProductionFreeSources() []string {
	out := make([]string, len(productionFreeSources))
	copy(out, productionFreeSources)
	return out
}

func RevisionKey(feedKey string) string {
	return normalizedFeedKey(feedKey) + ":revision"
}

func StatusKey(feedKey string, source string) string {
	return normalizedFeedKey(feedKey) + ":status:" + sourceID(feedKey, source)
}

func ReadStatusSummary(ctx context.Context, redisCache *cache.Redis, feedKey string, preset string, sources []string, staleAfter time.Duration) StatusSummary {
	feedKey = normalizedFeedKey(feedKey)
	sources = append([]string(nil), sources...)

	summary := StatusSummary{
		Configured: len(sources) > 0,
		Preset:     strings.TrimSpace(preset),
		FeedKey:    feedKey,
		Status:     "disabled",
	}
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}
	summary.StaleAfter = staleAfter.String()

	if len(sources) == 0 {
		return summary
	}

	summary.Status = "unknown"
	if redisCache == nil || !redisCache.Enabled() {
		summary.Status = "unavailable"
		summary.Error = cache.ErrDisabled.Error()
		summary.Sources = buildDefaultSourceStatuses(feedKey, sources, staleAfter)
		summary.Stale = true
		return summary
	}

	revision, err := redisCache.GetInt64(ctx, RevisionKey(feedKey))
	if err != nil {
		summary.Status = "unavailable"
		summary.Error = err.Error()
		summary.Sources = buildDefaultSourceStatuses(feedKey, sources, staleAfter)
		summary.Stale = true
		return summary
	}
	summary.Revision = revision
	activeEntries, err := redisCache.ZCount(ctx, feedKey, strconv.FormatInt(time.Now().Unix(), 10), "+inf")
	if err != nil {
		summary.Status = "unavailable"
		summary.Error = err.Error()
		summary.Sources = buildDefaultSourceStatuses(feedKey, sources, staleAfter)
		summary.Stale = true
		return summary
	}
	summary.ActiveEntries = activeEntries

	statuses := make([]SourceStatus, 0, len(sources))
	hasWarning := false
	for _, source := range sources {
		state := SourceStatus{
			Source:   source,
			SourceID: sourceID(feedKey, source),
			FeedKey:  feedKey,
			Status:   "never_synced",
		}
		found, err := redisCache.GetJSON(ctx, StatusKey(feedKey, source), &state)
		if err != nil {
			state.Status = "error"
			state.LastError = err.Error()
		}
		if !found && state.Status != "error" {
			state.Status = "never_synced"
		}
		applyStaleness(&state, staleAfter)

		if state.Stale {
			summary.Stale = true
		}
		if state.ParserDrift {
			summary.ParserDrift = true
		}
		if state.EmptyIngest {
			// Surfaced alongside ParserDrift rather than folded into it: both are
			// warnings, but an emptied source and a changed format need different
			// responses.
			summary.EmptyIngest = true
			hasWarning = true
		}
		if state.Status == "error" || state.ParserDrift {
			hasWarning = true
		}
		if laterTimestamp(state.LastAttemptAt, summary.LastAttemptAt) {
			summary.LastAttemptAt = state.LastAttemptAt
		}
		if laterTimestamp(state.LastSuccessAt, summary.LastSuccessAt) {
			summary.LastSuccessAt = state.LastSuccessAt
		}

		statuses = append(statuses, state)
	}

	summary.Sources = statuses
	switch {
	case summary.ActiveEntries == 0 && (summary.Revision > 0 || summary.LastSuccessAt != ""):
		summary.Status = "missing"
		summary.Error = "threat feed has no active entries after a recorded successful sync"
		summary.Stale = true
	case summary.Stale:
		summary.Status = "stale"
	case hasWarning:
		summary.Status = "warning"
	default:
		summary.Status = "ok"
	}
	return summary
}

func parserDriftDefaults(ratio float64, minInvalid int) (float64, int) {
	if ratio <= 0 {
		ratio = defaultParserDriftInvalidRatio
	}
	if minInvalid <= 0 {
		minInvalid = defaultParserDriftMinInvalid
	}
	return ratio, minInvalid
}

func cacheInvalidationMinWrites(value int64) int64 {
	if value <= 0 {
		return defaultCacheInvalidationWrites
	}
	return value
}

func parserDriftStatus(stats ParseStats, ratio float64, minInvalid int) (bool, string) {
	ratio, minInvalid = parserDriftDefaults(ratio, minInvalid)

	totalCandidates := stats.Valid + stats.Invalid
	if stats.Invalid < minInvalid || totalCandidates == 0 {
		return false, ""
	}

	invalidRatio := float64(stats.Invalid) / float64(totalCandidates)
	if invalidRatio < ratio {
		return false, ""
	}

	return true, fmt.Sprintf("invalid ratio %.0f%% (%d invalid / %d candidates)", invalidRatio*100, stats.Invalid, totalCandidates)
}

func recordSyncFailure(ctx context.Context, redisCache *cache.Redis, feedKey string, source string, syncErr error) error {
	if redisCache == nil || !redisCache.Enabled() {
		return cache.ErrDisabled
	}

	status := SourceStatus{
		Source:   source,
		SourceID: sourceID(feedKey, source),
		FeedKey:  normalizedFeedKey(feedKey),
	}
	_, _ = redisCache.GetJSON(ctx, StatusKey(feedKey, source), &status)

	now := time.Now().UTC().Format(time.RFC3339Nano)
	status.Status = "error"
	status.LastAttemptAt = now
	status.LastFailureAt = now
	status.LastError = syncErr.Error()
	status.FinishedAt = now
	status.Stale = true

	return redisCache.SetJSON(ctx, StatusKey(feedKey, source), status, 0)
}

func recordSyncSuccess(ctx context.Context, redisCache *cache.Redis, report SyncReport) error {
	if redisCache == nil || !redisCache.Enabled() {
		return cache.ErrDisabled
	}

	status := SourceStatus{
		Source:            report.Source,
		SourceID:          sourceID(report.Key, report.Source),
		FeedKey:           normalizedFeedKey(report.Key),
		Status:            "ok",
		LastAttemptAt:     report.FinishedAt,
		LastSuccessAt:     report.FinishedAt,
		Stats:             report.Stats,
		Written:           report.Written,
		Replace:           report.Replace,
		FinishedAt:        report.FinishedAt,
		ParserDrift:       report.ParserDrift,
		ParserDriftReason: report.ParserDriftReason,
		// Derived here rather than at the call sites so no sync path can forget
		// it: every path that reaches recordSyncSuccess has already decided the
		// sync succeeded, and a success with nothing in it is the case worth
		// surfacing.
		EmptyIngest:       report.Stats.Valid == 0,
		EmptyIngestReason: emptyIngestReason(report),
		CacheInvalidated:  report.CacheInvalidated,
		FeedRevision:      report.FeedRevision,
		Admission:         report.Admission,
		Shadow:            report.Shadow,
	}

	return redisCache.SetJSON(ctx, StatusKey(report.Key, report.Source), status, 0)
}

// emptyIngestReason explains a zero-valid sync in terms the operator can act on,
// distinguishing the shapes that produce it: a body that parsed to nothing, a body
// that was nothing but comments and blanks, and a body that was entirely invalid
// lines.
func emptyIngestReason(report SyncReport) string {
	if report.Stats.Valid != 0 {
		return ""
	}
	s := report.Stats
	switch {
	case s.Invalid > 0 && s.Skipped == 0:
		return fmt.Sprintf("all %d candidate lines were unparseable", s.Invalid)
	case s.Invalid == 0 && s.Skipped > 0:
		return fmt.Sprintf("all %d lines were comments or unparseable, none were domains", s.Skipped)
	case s.Invalid > 0:
		return fmt.Sprintf("%d invalid and %d skipped lines, no valid domain", s.Invalid, s.Skipped)
	default:
		return "the response body contained no candidate lines at all"
	}
}

func buildDefaultSourceStatuses(feedKey string, sources []string, staleAfter time.Duration) []SourceStatus {
	statuses := make([]SourceStatus, 0, len(sources))
	for _, source := range sources {
		state := SourceStatus{
			Source:   source,
			SourceID: sourceID(feedKey, source),
			FeedKey:  normalizedFeedKey(feedKey),
			Status:   "never_synced",
		}
		applyStaleness(&state, staleAfter)
		statuses = append(statuses, state)
	}
	return statuses
}

func applyStaleness(status *SourceStatus, staleAfter time.Duration) {
	if status == nil {
		return
	}
	status.Stale = true
	if staleAfter <= 0 {
		staleAfter = defaultStaleAfter
	}
	if strings.TrimSpace(status.LastSuccessAt) == "" {
		return
	}

	lastSuccess, err := time.Parse(time.RFC3339Nano, status.LastSuccessAt)
	if err != nil {
		return
	}
	status.Stale = time.Since(lastSuccess) > staleAfter
}

func normalizedFeedKey(feedKey string) string {
	feedKey = strings.TrimSpace(feedKey)
	if feedKey == "" {
		return DefaultThreatFeedKey
	}
	return feedKey
}

func sourceID(feedKey string, source string) string {
	sum := sha256.Sum256([]byte(normalizedFeedKey(feedKey) + "\n" + strings.TrimSpace(source)))
	return hex.EncodeToString(sum[:8])
}

func laterTimestamp(candidate string, current string) bool {
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}

	candidateTime, err := time.Parse(time.RFC3339Nano, candidate)
	if err != nil {
		return false
	}
	currentTime, err := time.Parse(time.RFC3339Nano, current)
	if err != nil {
		return true
	}
	return candidateTime.After(currentTime)
}
