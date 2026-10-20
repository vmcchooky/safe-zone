package feedsync

import (
	"context"
	"errors"
	"fmt"

	"safe-zone/internal/correlation"
	"safe-zone/internal/feed"
	"safe-zone/internal/logjson"
	"safe-zone/internal/netguard"
)

// RunCycle executes one feed sync for a single source and returns its
// report. The caller owns the context, which carries the run ID, and owns all
// success output: the one-shot prints an indented report to stdout while the
// daemon embeds a compact report in its completed log line. Failures are
// logged here under the caller's service name so both binaries report them
// identically.
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

// RunCycleAll executes one feed sync per configured source and returns the
// reports in configuration order.
//
// A source that fails does not stop the others: one provider being down must
// not take the remaining coverage with it. The returned error is non-nil when
// at least one source failed, so the one-shot can exit non-zero and the
// daemon can log the partial failure.
func RunCycleAll(ctx context.Context, settings Settings, serviceName string) ([]feed.SyncReport, error) {
	client := netguard.NewHTTPClient(nil, settings.Timeout, false)

	reports := make([]feed.SyncReport, 0, len(settings.Sources))
	var failures []error

	for _, source := range settings.Sources {
		report, err := feed.Sync(ctx, BuildSyncOptionsForSource(settings, client, source))
		if err != nil {
			logjson.Error("feed sync failed", correlation.Fields(ctx, map[string]any{
				"service": serviceName,
				"source":  source,
				"error":   err.Error(),
			}))
			failures = append(failures, fmt.Errorf("sync %s: %w", source, err))
			continue
		}
		reports = append(reports, report)
	}

	if len(failures) > 0 {
		return reports, errors.Join(failures...)
	}
	return reports, nil
}
