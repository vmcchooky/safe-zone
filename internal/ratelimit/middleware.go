package ratelimit

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"

	"safe-zone/internal/correlation"
	"safe-zone/internal/logjson"
)

// Tier maps a URL path prefix to a specific Limiter.
type Tier struct {
	PathPrefix string
	Limiter    *Limiter
}

// TieredMiddleware applies different rate limits based on request path prefix.
// The first matching Tier wins; fallback is used when no Tier matches.
type TieredMiddleware struct {
	tiers    []Tier
	fallback *Limiter
}

// NewTieredMiddleware creates a TieredMiddleware.
// tiers are checked in order; fallback is used when none match.
func NewTieredMiddleware(fallback *Limiter, tiers ...Tier) *TieredMiddleware {
	return &TieredMiddleware{
		tiers:    tiers,
		fallback: fallback,
	}
}

// Wrap returns an http.Handler that applies tiered rate limiting before
// calling next. A 429 response is written if the client exceeds their limit.
func (tm *TieredMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limiter := tm.limiterFor(r.URL.Path)
		ip := ClientIP(r)

		if !limiter.Allow(ip) {
			retryAfter := limiter.SecondsUntilNextToken(ip)
			secs := int(math.Ceil(retryAfter))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":               "rate limit exceeded",
				"retry_after_seconds": secs,
			})
			logjson.Warn("rate limited request", correlation.Fields(r.Context(), map[string]any{
				"client_ip": sanitizeLog(ip),
				"path":      sanitizeLog(r.URL.Path),
			})) // #nosec G706 -- request values are escaped by sanitizeLog before logging.
			return
		}
		next.ServeHTTP(w, r)
	})
}

// limiterFor returns the Limiter for the given path (first prefix match).
func (tm *TieredMiddleware) limiterFor(path string) *Limiter {
	for _, t := range tm.tiers {
		if strings.HasPrefix(path, t.PathPrefix) {
			return t.Limiter
		}
	}
	return tm.fallback
}

// Middleware wraps next with a single rate limiter keyed by client IP.
// Use TieredMiddleware when different endpoints need different limits.
func Middleware(limiter *Limiter, next http.Handler) http.Handler {
	tm := NewTieredMiddleware(limiter)
	return tm.Wrap(next)
}

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

var defaultTrustedProxies []net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",
		"::1/128",
		"172.16.0.0/12",
		"10.0.0.0/8",
		"192.168.0.0/16",
	}
	for _, c := range cidrs {
		_, ipNet, err := net.ParseCIDR(c)
		if err == nil {
			defaultTrustedProxies = append(defaultTrustedProxies, *ipNet)
		}
	}
}

func isTrustedProxy(ip string) bool {
	parsedIP := parseHeaderIP(ip)
	if parsedIP == nil {
		return false
	}
	return isTrustedProxyIP(parsedIP)
}

func isTrustedProxyIP(parsedIP net.IP) bool {
	for _, network := range defaultTrustedProxies {
		if network.Contains(parsedIP) {
			return true
		}
	}
	return false
}

func parseHeaderIP(value string) net.IP {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	return net.ParseIP(value)
}

func clientIPFromXForwardedFor(xff string) string {
	parts := strings.Split(xff, ",")
	valid := make([]net.IP, 0, len(parts))
	for _, part := range parts {
		if ip := parseHeaderIP(part); ip != nil {
			valid = append(valid, ip)
		}
	}
	if len(valid) == 0 {
		return ""
	}
	for i := len(valid) - 1; i >= 0; i-- {
		if !isTrustedProxyIP(valid[i]) {
			return valid[i].String()
		}
	}
	return valid[0].String()
}

// ClientIP extracts the real client IP from the request.
// Priority: X-Forwarded-For (rightmost non-trusted hop) → X-Real-IP → RemoteAddr.
// It only trusts X-Forwarded-For if the request comes from a trusted proxy.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	if isTrustedProxy(host) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if ip := clientIPFromXForwardedFor(xff); ip != "" {
				return ip
			}
		}
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			if ip := parseHeaderIP(xri); ip != nil {
				return ip.String()
			}
		}
	}

	return host
}
