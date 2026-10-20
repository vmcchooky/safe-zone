package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"safe-zone/internal/buildinfo"
	"safe-zone/internal/correlation"
	"safe-zone/internal/feedsync"
	"safe-zone/internal/logjson"
)

func main() {
	buildinfo.Link()

	flags := flag.NewFlagSet("feed-syncd", flag.ExitOnError)
	settings, err := feedsync.ParseSettings(feedsync.ModeDaemon, flags, os.Args[1:])
	if err != nil {
		logjson.Error("invalid feed sync daemon configuration", map[string]any{
			"service": "feed-syncd",
			"error":   err.Error(),
		})
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if settings.Replace {
		logjson.Warn("feed-syncd replace mode requires exclusive ownership of the feed key", map[string]any{
			"service": "feed-syncd",
			"source":  settings.Source,
			"key":     settings.Key,
		})
	}

	runSync := func() {
		runCtx := correlation.WithRunID(ctx, correlation.NewID("feed-syncd"))
		reports, err := feedsync.RunCycleAll(runCtx, settings, "feed-syncd")
		if err != nil {
			// One failing source does not take the others down, but the
			// partial failure is logged so it is not invisible.
			logjson.Error("feed sync completed with failures", correlation.Fields(runCtx, map[string]any{
				"service": "feed-syncd",
				"source":  settings.Source,
				"error":   err.Error(),
			}))
		}

		for _, report := range reports {
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				logjson.Error("feed sync report encode failed", correlation.Fields(runCtx, map[string]any{
					"service": "feed-syncd",
					"source":  settings.Source,
					"error":   marshalErr.Error(),
				}))
				continue
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

		// The oversize tripwire guards the shared key's memory. The one-shot
		// ran it, the daemon did not, so a daemon-driven deployment never
		// saw the warning.
		if !settings.DryRun && settings.RedisAddr != "" {
			feedsync.WarnIfFeedOversized(runCtx, settings.RedisAddr, settings.RedisPassword, settings.RedisDB, settings.Key)
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
