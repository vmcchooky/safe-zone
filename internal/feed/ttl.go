package feed

import (
	"errors"
	"fmt"
	"time"

	"safe-zone/internal/analysis"
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

// MinChurnTTLDays bounds the shortened churn TTL from below. A churn TTL must
// stay comfortably above the sync interval, otherwise a member that is still
// listed by its source would expire in the gap between two syncs and silently
// stop blocking. With the production interval at 24h, two days keeps a 2x
// margin; a non-positive value means "disabled" and is accepted as such.
const MinChurnTTLDays = 2

// ChurnTTLFromDays is the single contract for converting the configured
// churn-prone tenant TTL (SAFE_ZONE_FEED_CHURN_TTL_DAYS / --churn-ttl-days)
// into a duration, mirroring TTLFromDays so the two entrypoints, the daemon
// and the OSINT promotion cannot drift apart. Zero or negative disables the
// shortened window and every member expires on the base TTL. Any other value
// below MinChurnTTLDays is refused rather than silently clamped, because a
// too-short window trades away live protection for a precision gain.
//
// The short window is only safe while it stays above the sync interval, so the
// contract is deliberately a minimum rather than a free parameter.
func ChurnTTLFromDays(days int) (time.Duration, error) {
	if days <= 0 {
		return 0, nil
	}
	if days < MinChurnTTLDays {
		return 0, fmt.Errorf("churn-ttl-days must be 0 (disabled) or at least %d, got %d", MinChurnTTLDays, days)
	}
	return time.Duration(days) * 24 * time.Hour, nil
}

// CheckChurnTTLAgainstInterval guards the one failure mode that would silently
// cost protection: a churn window at or below the sync interval lets a member
// that is still listed by its source expire in the gap between two cycles. The
// feed package cannot see the interval, so each entrypoint calls this and
// refuses to start rather than under-blocking by configuration accident.
func CheckChurnTTLAgainstInterval(churn, interval time.Duration) error {
	if churn <= 0 {
		return nil
	}
	if interval <= 0 {
		return errors.New("sync interval must be positive to validate the churn TTL")
	}
	if churn <= interval {
		return fmt.Errorf("churn TTL %s must exceed the sync interval %s, otherwise members expire between cycles", churn, interval)
	}
	return nil
}

// MemberTTL returns the expiry window for one feed member. A non-positive
// churn window disables the split, so the base TTL is used unchanged.
//
// Shortening the window does not weaken live protection: sync re-scores every
// member on every run, so an entry that is still listed by its source keeps its
// expiry pushed forward indefinitely. The shortened window only decides how
// fast a member disappears after it drops out of the source, which is exactly
// the recycled-label case this exists for.
func MemberTTL(domain string, base, churn time.Duration) time.Duration {
	if base <= 0 {
		base = DefaultSyncTTL
	}
	if churn <= 0 || !analysis.IsChurnProneTenant(domain) {
		return base
	}
	if churn >= base {
		return base
	}
	return churn
}
