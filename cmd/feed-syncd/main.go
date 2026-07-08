package main

import (
	"context"
	"encoding/json"
	"flag"
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

func main() {
	buildinfo.Link()

	source := flag.String("source", config.String("SAFE_ZONE_THREAT_FEED_SOURCE", ""), "local file path or HTTP(S) feed URL")
	redisAddr := flag.String("redis-addr", config.String("SAFE_ZONE_REDIS_ADDR", ""), "Redis address")
	redisPassword := flag.String("redis-password", config.SecretString("SAFE_ZONE_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flag.Int("redis-db", config.Int("SAFE_ZONE_REDIS_DB", 0), "Redis database")
	key := flag.String("key", config.String("SAFE_ZONE_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis Set key for threat feed")
	replace := flag.Bool("replace", true, "delete the target set before writing parsed domains")
	once := flag.Bool("once", false, "run one sync cycle and exit")
	interval := flag.Duration("interval", config.DurationSeconds("SAFE_ZONE_FEED_SYNC_INTERVAL_SECONDS", 24*time.Hour), "time between sync cycles")
	timeout := flag.Duration("timeout", config.DurationMillis("SAFE_ZONE_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		logjson.Error("feed source is required", map[string]any{
			"service": "feed-syncd",
		})
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	runSync := func() {
		runCtx := correlation.WithRunID(ctx, correlation.NewID("feed-syncd"))
		client := netguard.NewHTTPClient(nil, *timeout, false)
		report, err := feed.Sync(runCtx, feed.SyncOptions{
			Source:                     *source,
			FileRoot:                   config.FeedFileRoot(),
			MaxBytes:                   int64(config.Int("SAFE_ZONE_FEED_MAX_BYTES", int(feed.DefaultMaxFeedBytes))),
			RedisAddr:                  *redisAddr,
			RedisPassword:              *redisPassword,
			RedisDB:                    *redisDB,
			Key:                        *key,
			Replace:                    *replace,
			Timeout:                    *timeout,
			Client:                     client,
			ParserDriftInvalidRatio:    config.Float64("SAFE_ZONE_FEED_DRIFT_INVALID_RATIO", 0.20),
			ParserDriftMinInvalid:      config.Int("SAFE_ZONE_FEED_DRIFT_MIN_INVALID", 25),
			CacheInvalidationMinWrites: int64(config.Int("SAFE_ZONE_FEED_CACHE_INVALIDATION_MIN_WRITES", 1)),
		})
		if err != nil {
			logjson.Error("feed sync failed", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  *source,
				"error":   err.Error(),
			}))
			return
		}

		encoded, marshalErr := json.Marshal(report)
		if marshalErr != nil {
			logjson.Error("feed sync report encode failed", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  *source,
				"error":   marshalErr.Error(),
			}))
			return
		}

		logjson.Info("feed sync completed", correlation.Fields(runCtx, map[string]any{
			"service": "feed-syncd",
			"source":  *source,
			"written": report.Written,
			"valid":   report.Stats.Valid,
			"invalid": report.Stats.Invalid,
			"report":  string(encoded),
		}))
		if report.ParserDrift {
			logjson.Warn("feed sync parser drift", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  *source,
				"reason":  report.ParserDriftReason,
			}))
		}
	}

	runSync()
	if *once {
		return
	}

	ticker := time.NewTicker(*interval)
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
