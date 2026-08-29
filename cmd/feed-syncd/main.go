package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"safe-zone/internal/buildinfo"
	"safe-zone/internal/config"
	"safe-zone/internal/correlation"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
)

var (
	errSourceRequired       = errors.New("feed source is required")
	errFilterEvaluationOnly = errors.New("corroborated URL-host filter is evaluation-only")
)

// syncSettings is the resolved configuration of one daemon run. It is
// separated from flag parsing so the effective options are testable.
type syncSettings struct {
	Source        string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Key           string
	Replace       bool
	Once          bool
	Interval      time.Duration
	Timeout       time.Duration
	AdmissionMode feed.AdmissionMode
	TTL           time.Duration
}

func main() {
	buildinfo.Link()

	settings, err := parseSyncSettings(flag.CommandLine, os.Args[1:])
	if err != nil {
		logjson.Error("invalid feed sync daemon configuration", map[string]any{
			"service": "feed-syncd",
			"error":   err.Error(),
		})
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runSync := func() {
		runCtx := correlation.WithRunID(ctx, correlation.NewID("feed-syncd"))
		client := netguard.NewHTTPClient(nil, settings.Timeout, false)
		report, err := feed.Sync(runCtx, buildSyncOptions(settings, client))
		if err != nil {
			logjson.Error("feed sync failed", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  settings.Source,
				"error":   err.Error(),
			}))
			return
		}

		encoded, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			logjson.Error("feed sync report encode failed", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  settings.Source,
				"error":   marshalErr.Error(),
			}))
			return
		}

		logjson.Info("feed sync completed", correlation.Fields(runCtx, map[string]any{
			"service": "feed-syncd",
			"source":  settings.Source,
			"written": report.Written,
			"valid":   report.Stats.Valid,
			"invalid": report.Stats.Invalid,
			"report":  string(encoded),
		}))
		if report.ParserDrift {
			logjson.Warn("feed sync parser drift", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  settings.Source,
				"reason":  report.ParserDriftReason,
			}))
		}
	}

	runSync()
	if settings.Once {
		return
	}

	ticker := time.NewTicker(settings.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runSync()
		}
	}
}

// parseSyncSettings mirrors the flag surface of the one-shot feed-sync tool
// (--ttl-days and SAFE_ZONE_FEED_TTL_DAYS included) so the two entrypoints
// resolve identical effective options.
func parseSyncSettings(flags *flag.FlagSet, args []string) (syncSettings, error) {
	source := flags.String("source", config.String("SAFE_ZONE_THREAT_FEED_SOURCE", ""), "local file path or HTTP(S) feed URL")
	redisAddr := flags.String("redis-addr", config.String("SAFE_ZONE_REDIS_ADDR", ""), "Redis address")
	redisPassword := flags.String("redis-password", config.SecretString("SAFE_ZONE_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flags.Int("redis-db", config.Int("SAFE_ZONE_REDIS_DB", 0), "Redis database")
	key := flags.String("key", config.String("SAFE_ZONE_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis Set key for threat feed")
	replace := flags.Bool("replace", true, "delete the target set before writing parsed domains")
	once := flags.Bool("once", false, "run one sync cycle and exit")
	interval := flags.Duration("interval", config.DurationSeconds("SAFE_ZONE_FEED_SYNC_INTERVAL_SECONDS", 24*time.Hour), "time between sync cycles")
	timeout := flags.Duration("timeout", config.DurationMillis("SAFE_ZONE_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	admissionMode := flags.String("admission-mode", config.String("SAFE_ZONE_FEED_ADMISSION_MODE", string(feed.AdmissionLegacy)), "feed admission mode: legacy, corroborated-url-host-shadow, or corroborated-url-host-filter")
	ttlDays := flags.Int("ttl-days", config.Int("SAFE_ZONE_FEED_TTL_DAYS", 14), "number of days before threat domains expire")
	if err := flags.Parse(args); err != nil {
		return syncSettings{}, err
	}

	feedTTL, ttlErr := feed.TTLFromDays(*ttlDays)
	if ttlErr != nil {
		return syncSettings{}, ttlErr
	}
	normalizedAdmissionMode, admissionErr := feed.NormalizeAdmissionMode(*admissionMode)
	if admissionErr != nil {
		return syncSettings{}, admissionErr
	}
	if normalizedAdmissionMode == feed.AdmissionFilter {
		return syncSettings{}, errFilterEvaluationOnly
	}
	if strings.TrimSpace(*source) == "" {
		return syncSettings{}, errSourceRequired
	}

	return syncSettings{
		Source:        *source,
		RedisAddr:     *redisAddr,
		RedisPassword: *redisPassword,
		RedisDB:       *redisDB,
		Key:           *key,
		Replace:       *replace,
		Once:          *once,
		Interval:      *interval,
		Timeout:       *timeout,
		AdmissionMode: normalizedAdmissionMode,
		TTL:           feedTTL,
	}, nil
}

// buildSyncOptions assembles the feed.Sync contract from the resolved
// settings.
func buildSyncOptions(settings syncSettings, client *http.Client) feed.SyncOptions {
	return feed.SyncOptions{
		Source:                     settings.Source,
		FileRoot:                   config.FeedFileRoot(),
		MaxBytes:                   int64(config.Int("SAFE_ZONE_FEED_MAX_BYTES", int(feed.DefaultMaxFeedBytes))),
		RedisAddr:                  settings.RedisAddr,
		RedisPassword:              settings.RedisPassword,
		RedisDB:                    settings.RedisDB,
		Key:                        settings.Key,
		Replace:                    settings.Replace,
		Timeout:                    settings.Timeout,
		Client:                     client,
		ParserDriftInvalidRatio:    config.Float64("SAFE_ZONE_FEED_DRIFT_INVALID_RATIO", 0.20),
		ParserDriftMinInvalid:      config.Int("SAFE_ZONE_FEED_DRIFT_MIN_INVALID", 25),
		CacheInvalidationMinWrites: int64(config.Int("SAFE_ZONE_FEED_CACHE_INVALIDATION_MIN_WRITES", 1)),
		TTL:                        settings.TTL,
		AdmissionMode:              settings.AdmissionMode,
	}
}
