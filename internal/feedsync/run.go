package feedsync

import (
	"context"

	"safe-zone/internal/correlation"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
)

// RunCycle executes one feed sync and returns its report. The caller owns the
// context, which carries the run ID, and owns all success output: the one-shot
// prints an indented report to stdout while the daemon embeds a compact report
// in its completed log line. Failures are logged here under the caller's
// service name so both binaries report them identically.
func RunCycle(ctx context.Context, settings Settings, serviceName string) (feed.SyncReport, error) {
	client := netguard.NewHTTPClient(nil, settings.Timeout, false)
	report, err := feed.Sync(ctx, BuildSyncOptions(settings, client))
	if err != nil {
		logjson.Error("feed sync failed", correlation.Fields(ctx, map[string]any{
			"service": serviceName,
			"source":  settings.Source,
			"error":   err.Error(),
		}))
		return feed.SyncReport{}, err
	}
	return report, nil
}
