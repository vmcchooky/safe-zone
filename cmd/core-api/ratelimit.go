package main

import (
	"safe-zone/internal/config"
	"safe-zone/internal/ratelimit"
)

// newTieredMiddleware builds the per-path rate limiter set from
// environment with compiled-in defaults. Extracted from main so the
// prefix-to-limiter wiring is unit-testable: a missing tier silently
// falls back to the default limiter, which has masked gaps before
// (/block/report had none until the report tier below).
func newTieredMiddleware() (*ratelimit.TieredMiddleware, func()) {
	authLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_AUTH_RPM", 8), config.Int("SAFE_ZONE_RATELIMIT_AUTH_BURST", 3))
	analyzeLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_ANALYZE_RPM", 10), config.Int("SAFE_ZONE_RATELIMIT_ANALYZE_BURST", 5))
	dashboardLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DASHBOARD_RPM", 240), config.Int("SAFE_ZONE_RATELIMIT_DASHBOARD_BURST", 60))
	overrideLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_OVERRIDE_RPM", 20), config.Int("SAFE_ZONE_RATELIMIT_OVERRIDE_BURST", 5))
	telemetryLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_TELEMETRY_RPM", 30), config.Int("SAFE_ZONE_RATELIMIT_TELEMETRY_BURST", 10))
	feedbackLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_FEEDBACK_RPM", 30), config.Int("SAFE_ZONE_RATELIMIT_FEEDBACK_BURST", 10))
	reportLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_REPORT_RPM", 10), config.Int("SAFE_ZONE_RATELIMIT_REPORT_BURST", 3))
	defaultLimiter := ratelimit.New(config.Float64("SAFE_ZONE_RATELIMIT_DEFAULT_RPM", 60), config.Int("SAFE_ZONE_RATELIMIT_DEFAULT_BURST", 15))
	stop := func() {
		authLimiter.Close()
		analyzeLimiter.Close()
		dashboardLimiter.Close()
		overrideLimiter.Close()
		telemetryLimiter.Close()
		feedbackLimiter.Close()
		reportLimiter.Close()
		defaultLimiter.Close()
	}
	tiered := ratelimit.NewTieredMiddleware(
		defaultLimiter,
		ratelimit.Tier{PathPrefix: "/v1/auth/login", Limiter: authLimiter},
		ratelimit.Tier{PathPrefix: "/v1/analyze", Limiter: analyzeLimiter},
		ratelimit.Tier{PathPrefix: "/v1/url-ml/feedback", Limiter: feedbackLimiter},
		ratelimit.Tier{PathPrefix: "/block/report", Limiter: reportLimiter},
		ratelimit.Tier{PathPrefix: "/assets/", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/app", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/dashboard", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/v1/status", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/metrics", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/v1/version", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/v1/auth/session", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/v1/settings/bundle", Limiter: dashboardLimiter},
		ratelimit.Tier{PathPrefix: "/v1/overrides", Limiter: overrideLimiter},
		ratelimit.Tier{PathPrefix: "/v1/brands", Limiter: overrideLimiter},
		ratelimit.Tier{PathPrefix: "/v1/telemetry", Limiter: telemetryLimiter},
	)
	return tiered, stop
}
