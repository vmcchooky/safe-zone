package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
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
	dryRun := flag.Bool("dry-run", false, "parse feed and report counts without writing Redis")
	replace := flag.Bool("replace", false, "delete the target set before writing parsed domains")
	timeout := flag.Duration("timeout", config.DurationMillis("SAFE_ZONE_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	ttlDays := flag.Int("ttl-days", config.Int("SAFE_ZONE_FEED_TTL_DAYS", 14), "number of days before threat domains expire")
	flag.Parse()

	if strings.TrimSpace(*source) == "" {
		logjson.Error("feed source is required", map[string]any{
			"service": "feed-sync",
			"source":  strings.TrimSpace(*source),
		})
		os.Exit(1)
	}

	ctx := correlation.WithRunID(context.Background(), correlation.NewID("feed-sync"))
	client := netguard.NewHTTPClient(nil, *timeout, false)
	report, err := feed.Sync(ctx, feed.SyncOptions{
		Source:                     *source,
		FileRoot:                   config.FeedFileRoot(),
		MaxBytes:                   int64(config.Int("SAFE_ZONE_FEED_MAX_BYTES", int(feed.DefaultMaxFeedBytes))),
		RedisAddr:                  *redisAddr,
		RedisPassword:              *redisPassword,
		RedisDB:                    *redisDB,
		Key:                        *key,
		DryRun:                     *dryRun,
		Replace:                    *replace,
		Timeout:                    *timeout,
		Client:                     client,
		ParserDriftInvalidRatio:    config.Float64("SAFE_ZONE_FEED_DRIFT_INVALID_RATIO", 0.20),
		ParserDriftMinInvalid:      config.Int("SAFE_ZONE_FEED_DRIFT_MIN_INVALID", 25),
		CacheInvalidationMinWrites: int64(config.Int("SAFE_ZONE_FEED_CACHE_INVALIDATION_MIN_WRITES", 1)),
		TTL:                        time.Duration(*ttlDays) * 24 * time.Hour,
	})
	if err != nil {
		logjson.Error("feed sync failed", correlation.Fields(ctx, map[string]any{
			"service": "feed-sync",
			"source":  *source,
			"error":   err.Error(),
		}))
		os.Exit(1)
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logjson.Error("feed sync report encode failed", correlation.Fields(ctx, map[string]any{
			"service": "feed-sync",
			"error":   err.Error(),
		}))
		os.Exit(1)
	}

	logjson.Info("feed sync completed", correlation.Fields(ctx, map[string]any{
		"service": "feed-sync",
		"source":  *source,
		"written": report.Written,
		"valid":   report.Stats.Valid,
		"invalid": report.Stats.Invalid,
	}))
	fmt.Println(string(encoded))
}
