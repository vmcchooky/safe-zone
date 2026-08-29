package feed

import (
	"fmt"
	"time"
)

// TTLFromDays is the single contract for converting the configured feed TTL
// (SAFE_ZONE_FEED_TTL_DAYS / --ttl-days) into a duration. Both sync
// entrypoints and the core-api OSINT promotion share it so their expiry
// semantics cannot drift apart. Non-positive values are rejected.
func TTLFromDays(days int) (time.Duration, error) {
	if days <= 0 {
		return 0, fmt.Errorf("ttl-days must be positive, got %d", days)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}
