package main

import (
	"fmt"

	"safe-zone/internal/config"
)

// feedConfigurationProblem reports why the threat feed configuration cannot
// protect anything, or nil when it can.
//
// A source set alone is not enough. The agent task is opt-in
// (SAFE_ZONE_AGENT_ENABLED defaults to false) and the feed-syncd daemon
// reads a different variable, so a preset with neither the agent nor the
// daemon configured would satisfy a "is a source configured" check while
// nothing ever populates the feed.
//
// Outside production the check does not apply: a local run without a feed
// is a normal local run.
func feedConfigurationProblem(feedSources []string, agentEnabled bool, daemonSource string) error {
	if !config.IsProduction() {
		return nil
	}
	if len(feedSources) == 0 {
		return fmt.Errorf(
			"no threat feed source is configured, so domains listed as malicious by a feed are not blocked; " +
				"set SAFE_ZONE_AGENT_FEED_PRESET=production-free or list SAFE_ZONE_AGENT_FEED_SOURCES explicitly",
		)
	}
	if !agentEnabled && daemonSource == "" {
		return fmt.Errorf(
			"a threat feed source is configured but nothing syncs it: the agent task is opt-in " +
				"(SAFE_ZONE_AGENT_ENABLED) and the feed-syncd daemon reads SAFE_ZONE_THREAT_FEED_SOURCE",
		)
	}
	return nil
}
