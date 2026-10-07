// Package feedsync holds the entrypoint logic shared by the feed-sync
// one-shot tool and the feed-syncd daemon: flag parsing with identical
// defaults and validation, assembly of the feed.Sync contract, one sync
// cycle, and the shared-key growth tripwire.
//
// The two binaries keep their own CLIs and runtime behavior (one-shot prints
// a report and exits non-zero on failure; the daemon loops on a ticker and
// keeps going), but every rule about what counts as a valid configuration
// lives here exactly once. Historically the two mains drifted: the daemon
// validated admission mode, churn windows and the interval while the
// one-shot passed them through raw. Unifying on the strict set can only
// turn silent misconfiguration into loud errors.
package feedsync

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/feed"
)

var (
	errSourceRequired       = errors.New("feed source is required")
	errFilterEvaluationOnly = errors.New("corroborated URL-host filter is evaluation-only")
)

// Mode selects which entrypoint surface ParseSettings parses. The common
// flags are identical in both modes; each mode adds only its own: --dry-run
// for the one-shot, --once and --interval for the daemon.
type Mode int

const (
	ModeOneShot Mode = iota + 1
	ModeDaemon
)

// Settings is the resolved configuration of one sync run. It is separated
// from flag parsing so the effective options are testable.
type Settings struct {
	Source        string
	RedisAddr     string
	RedisPassword string
	RedisDB       int
	Key           string
	Replace       bool
	AllowInsecure bool
	DryRun        bool
	Once          bool
	Interval      time.Duration
	Timeout       time.Duration
	AdmissionMode feed.AdmissionMode
	TTL           time.Duration
	// ChurnTTL is the shortened window for recycled-label members. It is
	// validated in ParseSettings to exceed Interval, so a still-listed
	// member can never expire in the gap between two cycles.
	ChurnTTL time.Duration
}

// ParseSettings mirrors the flag surface of both feed tools so the two
// entrypoints resolve identical effective options. Validation is shared:
// TTL and churn windows, admission mode (normalized, with the
// evaluation-only filter mode refused), and a non-empty source are refused
// for both binaries, not just the daemon.
func ParseSettings(mode Mode, flags *flag.FlagSet, args []string) (Settings, error) {
	source := flags.String("source", config.String("SAFE_ZONE_THREAT_FEED_SOURCE", ""), "local file path or HTTP(S) feed URL")
	redisAddr := flags.String("redis-addr", config.String("SAFE_ZONE_REDIS_ADDR", ""), "Redis address")
	redisPassword := flags.String("redis-password", config.SecretString("SAFE_ZONE_REDIS_PASSWORD", ""), "Redis password")
	redisDB := flags.Int("redis-db", config.Int("SAFE_ZONE_REDIS_DB", 0), "Redis database")
	key := flags.String("key", config.String("SAFE_ZONE_THREAT_FEED_KEY", feed.DefaultThreatFeedKey), "Redis Set key for threat feed")
	// Replace defaults to false: whole-key staging renames would wipe other
	// writers sharing the feed key (one daemon per source, or the one-shot
	// loop). Single-source freshness then rests on per-member TTL expiry.
	// Enable -replace only when this process owns its key exclusively.
	replace := flags.Bool("replace", false, "delete the target set before writing parsed domains (requires exclusive key ownership)")
	allowInsecure := flags.Bool("allow-insecure-http", config.Bool("SAFE_ZONE_FEED_ALLOW_INSECURE_HTTP", false), "allow plain-HTTP feed fetch (MITM can inject mass blocks; prefer https)")
	timeout := flags.Duration("timeout", config.DurationMillis("SAFE_ZONE_FEED_SYNC_TIMEOUT_MS", 30*time.Second), "feed read and Redis write timeout")
	admissionMode := flags.String("admission-mode", config.String("SAFE_ZONE_FEED_ADMISSION_MODE", string(feed.AdmissionLegacy)), "feed admission mode: legacy, corroborated-url-host-shadow, or corroborated-url-host-filter")
	ttlDays := flags.Int("ttl-days", config.Int("SAFE_ZONE_FEED_TTL_DAYS", 14), "number of days before threat domains expire")
	churnTTLDays := flags.Int("churn-ttl-days", config.Int("SAFE_ZONE_FEED_CHURN_TTL_DAYS", 0), "shorter expiry in days for members on recycled-label roots (0 disables; must be at least 2 and above the sync interval)")

	var dryRun *bool
	var once *bool
	var interval *time.Duration
	switch mode {
	case ModeOneShot:
		dryRun = flags.Bool("dry-run", false, "parse feed and report counts without writing Redis")
	case ModeDaemon:
		once = flags.Bool("once", false, "run one sync cycle and exit")
		interval = flags.Duration("interval", config.DurationSeconds("SAFE_ZONE_FEED_SYNC_INTERVAL_SECONDS", 24*time.Hour), "time between sync cycles")
	default:
		return Settings{}, fmt.Errorf("unknown feed sync mode %d", int(mode))
	}

	if err := flags.Parse(args); err != nil {
		return Settings{}, err
	}
	if mode == ModeDaemon {
		// time.NewTicker panics on a non-positive duration, and
		// CheckChurnTTLAgainstInterval below only reaches the interval when a churn
		// window is configured — with the default churn of 0 it returns nil
		// immediately, so an explicit --interval=0 or a
		// SAFE_ZONE_FEED_SYNC_INTERVAL_SECONDS=0 reached the ticker and crashed the
		// daemon instead of being refused. Validate it here, where the other inputs are
		// refused, rather than at the point of use.
		if *interval <= 0 {
			return Settings{}, fmt.Errorf("interval must be positive, got %s", *interval)
		}
	}

	feedTTL, ttlErr := feed.TTLFromDays(*ttlDays)
	if ttlErr != nil {
		return Settings{}, ttlErr
	}
	churnTTL, churnErr := feed.ChurnTTLFromDays(*churnTTLDays)
	if churnErr != nil {
		return Settings{}, churnErr
	}
	normalizedAdmissionMode, admissionErr := feed.NormalizeAdmissionMode(*admissionMode)
	if mode == ModeDaemon {
		// The churn window only constrains a repeating schedule. The one-shot
		// has no interval, so there is nothing to check it against.
		if err := feed.CheckChurnTTLAgainstInterval(churnTTL, *interval); err != nil {
			return Settings{}, err
		}
	}
	if admissionErr != nil {
		return Settings{}, admissionErr
	}
	if normalizedAdmissionMode == feed.AdmissionFilter {
		return Settings{}, errFilterEvaluationOnly
	}
	if strings.TrimSpace(*source) == "" {
		return Settings{}, errSourceRequired
	}

	settings := Settings{
		Source:        *source,
		RedisAddr:     *redisAddr,
		RedisPassword: *redisPassword,
		RedisDB:       *redisDB,
		Key:           *key,
		Replace:       *replace,
		AllowInsecure: *allowInsecure,
		Timeout:       *timeout,
		AdmissionMode: normalizedAdmissionMode,
		TTL:           feedTTL,
		ChurnTTL:      churnTTL,
	}
	if mode == ModeOneShot {
		settings.DryRun = *dryRun
	} else {
		settings.Once = *once
		settings.Interval = *interval
	}
	return settings, nil
}

// BuildSyncOptions assembles the feed.Sync contract from the resolved
// settings.
func BuildSyncOptions(settings Settings, client *http.Client) feed.SyncOptions {
	return feed.SyncOptions{
		Source:                     settings.Source,
		FileRoot:                   config.FeedFileRoot(),
		MaxBytes:                   int64(config.Int("SAFE_ZONE_FEED_MAX_BYTES", int(feed.DefaultMaxFeedBytes))),
		RedisAddr:                  settings.RedisAddr,
		RedisPassword:              settings.RedisPassword,
		RedisDB:                    settings.RedisDB,
		Key:                        settings.Key,
		DryRun:                     settings.DryRun,
		Replace:                    settings.Replace,
		AllowInsecureHTTP:          settings.AllowInsecure,
		Timeout:                    settings.Timeout,
		Client:                     client,
		ParserDriftInvalidRatio:    config.Float64("SAFE_ZONE_FEED_DRIFT_INVALID_RATIO", 0.20),
		ParserDriftMinInvalid:      config.Int("SAFE_ZONE_FEED_DRIFT_MIN_INVALID", 25),
		CacheInvalidationMinWrites: int64(config.Int("SAFE_ZONE_FEED_CACHE_INVALIDATION_MIN_WRITES", 1)),
		TTL:                        settings.TTL,
		ChurnTTL:                   settings.ChurnTTL,
		AdmissionMode:              settings.AdmissionMode,
	}
}
