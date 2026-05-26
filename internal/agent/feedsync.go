package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"safe-zone/internal/correlation"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/store"
)

// FeedSyncConfig holds configuration for the multi-source feed sync task.
type FeedSyncConfig struct {
	Sources                    []string // Feed URLs (comma-separated in env)
	FileRoot                   string
	MaxBytes                   int64
	RedisAddr                  string
	RedisPassword              string
	RedisDB                    int
	FeedKey                    string
	Timeout                    time.Duration
	ParserDriftInvalidRatio    float64
	ParserDriftMinInvalid      int
	CacheInvalidationMinWrites int64
}

// FeedSyncTask downloads threat feed data from multiple sources and adds
// them to the Redis threat feed set.
type FeedSyncTask struct {
	store  *store.DB
	config FeedSyncConfig
}

// NewFeedSyncTask creates a FeedSyncTask with the given configuration.
func NewFeedSyncTask(db *store.DB, cfg FeedSyncConfig) *FeedSyncTask {
	if cfg.FeedKey == "" {
		cfg.FeedKey = feed.DefaultThreatFeedKey
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.FileRoot == "" {
		cfg.FileRoot = "./data"
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = feed.DefaultMaxFeedBytes
	}
	return &FeedSyncTask{
		store:  db,
		config: cfg,
	}
}

func (t *FeedSyncTask) Name() string { return "feedsync" }

func (t *FeedSyncTask) Run(ctx context.Context) error {
	if len(t.config.Sources) == 0 {
		return nil // no sources configured, nothing to do
	}
	if strings.TrimSpace(t.config.RedisAddr) == "" {
		return nil // Redis required for feed sync
	}

	var (
		sourcesOK     int
		sourcesFailed int
		totalWritten  int64
	)

	for _, source := range t.config.Sources {
		source = strings.TrimSpace(source)
		if source == "" {
			continue
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		report, err := feed.Sync(ctx, feed.SyncOptions{
			Source:                     source,
			FileRoot:                   t.config.FileRoot,
			MaxBytes:                   t.config.MaxBytes,
			RedisAddr:                  t.config.RedisAddr,
			RedisPassword:              t.config.RedisPassword,
			RedisDB:                    t.config.RedisDB,
			Key:                        t.config.FeedKey,
			DryRun:                     false,
			Replace:                    false, // additive mode — don't delete existing entries
			Timeout:                    t.config.Timeout,
			ParserDriftInvalidRatio:    t.config.ParserDriftInvalidRatio,
			ParserDriftMinInvalid:      t.config.ParserDriftMinInvalid,
			CacheInvalidationMinWrites: t.config.CacheInvalidationMinWrites,
		})
		if err != nil {
			logjson.Error("agent feed sync failed", correlation.Fields(ctx, map[string]any{
				"service": "core-api",
				"task":    "feedsync",
				"source":  source,
				"error":   err.Error(),
			}))
			sourcesFailed++

			if t.store != nil && t.store.Enabled() {
				details := fmt.Sprintf(`{"source":"%s","error":"%s"}`, source, err.Error())
				_ = t.store.RecordAgentEvent("feedsync", "feed_error", "", details)
			}
			continue
		}

		sourcesOK++
		totalWritten += report.Written

		if t.store != nil && t.store.Enabled() {
			detailsJSON, _ := json.Marshal(report)
			_ = t.store.RecordAgentEvent("feedsync", "feed_synced", "", string(detailsJSON))
			if report.ParserDrift {
				_ = t.store.RecordAgentEvent("feedsync", "feed_parser_drift", "", string(detailsJSON))
			}
		}

		logjson.Info("agent feed sync completed", correlation.Fields(ctx, map[string]any{
			"service":     "core-api",
			"task":        "feedsync",
			"source":      source,
			"written":     report.Written,
			"valid":       report.Stats.Valid,
			"invalid":     report.Stats.Invalid,
			"request_key": report.Key,
		}))
		if report.ParserDrift {
			logjson.Warn("agent feed parser drift", correlation.Fields(ctx, map[string]any{
				"service": "core-api",
				"task":    "feedsync",
				"source":  source,
				"reason":  report.ParserDriftReason,
			}))
		}
	}

	summary := fmt.Sprintf(`{"sources_ok":%d,"sources_failed":%d,"total_written":%d}`,
		sourcesOK, sourcesFailed, totalWritten)
	if t.store != nil && t.store.Enabled() {
		_ = t.store.RecordAgentEvent("feedsync", "feedsync_completed", "", summary)
	}

	logjson.Info("agent feed sync cycle done", correlation.Fields(ctx, map[string]any{
		"service":        "core-api",
		"task":           "feedsync",
		"sources_ok":     sourcesOK,
		"sources_failed": sourcesFailed,
		"total_written":  totalWritten,
	}))

	if sourcesFailed > 0 && sourcesOK == 0 {
		return fmt.Errorf("all %d feed sources failed", sourcesFailed)
	}
	return nil
}
