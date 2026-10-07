package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"safe-zone/internal/buildinfo"
	"safe-zone/internal/correlation"
	"safe-zone/internal/feedsync"
	"safe-zone/internal/logjson"
)

func main() {
	buildinfo.Link()

	flags := flag.NewFlagSet("feed-sync", flag.ExitOnError)
	settings, err := feedsync.ParseSettings(feedsync.ModeOneShot, flags, os.Args[1:])
	if err != nil {
		logjson.Error("invalid feed sync configuration", map[string]any{
			"service": "feed-sync",
			"error":   err.Error(),
		})
		os.Exit(1)
	}
	// On the shared default key, one --replace invocation stages only its own
	// source and then renames over the live set, deleting everything the other
	// sources wrote. Nothing in internal/feed can know the key is shared, so
	// the warning belongs at this layer.
	if settings.Replace {
		logjson.Warn("feed-sync replace mode requires exclusive ownership of the feed key", map[string]any{
			"service": "feed-sync",
			"source":  settings.Source,
			"key":     settings.Key,
		})
	}

	ctx := correlation.WithRunID(context.Background(), correlation.NewID("feed-sync"))
	report, err := feedsync.RunCycle(ctx, settings, "feed-sync")
	if err != nil {
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
		"source":  settings.Source,
		"written": report.Written,
		"valid":   report.Stats.Valid,
		"invalid": report.Stats.Invalid,
	}))
	fmt.Println(string(encoded))

	if !settings.DryRun && strings.TrimSpace(settings.RedisAddr) != "" {
		feedsync.WarnIfFeedOversized(ctx, settings.RedisAddr, settings.RedisPassword, settings.RedisDB, settings.Key)
	}
}
