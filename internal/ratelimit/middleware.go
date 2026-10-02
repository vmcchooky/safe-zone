package ratelimit

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"safe-zone/internal/config"
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

func sanitizeLog(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
}

// TrustedProxiesEnv names the environment variable that decides which peers
// may set X-Forwarded-For / X-Real-IP.
const TrustedProxiesEnv = "SAFE_ZONE_TRUSTED_PROXIES"

// DefaultTrustedProxies is deliberately loopback-only. Trusting the whole
// RFC1918 space meant any host on the LAN could pick its own rate-limit key by
// setting X-Forwarded-For, which restored full brute-force throughput against
// the single bcrypt-guarded admin credential. Container deployments that put
// a reverse proxy in front of the service must list their proxy network
// explicitly (docker-compose.yml does this for the Compose bridge network).
const DefaultTrustedProxies = "127.0.0.0/8,::1/128"

var (
	trustedProxiesMu sync.RWMutex
	trustedProxies   []net.IPNet
)

// ParseTrustedProxies parses a comma-separated CIDR list. Blank entries are
// ignored; a malformed entry is an error so the caller can fail closed rather
// than silently trusting fewer proxies than the operator configured.
func ParseTrustedProxies(list string) ([]net.IPNet, error) {
	var parsed []net.IPNet
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("parse trusted proxy %q: %w", entry, err)
		}
		parsed = append(parsed, *network)
	}
	return parsed, nil
}

// SetTrustedProxies replaces the trusted proxy list. It exists so tests can
// pin the trust decision without mutating process-wide environment state, and
// so the lazily-resolved configuration can be replaced once resolved.
func SetTrustedProxies(nets []net.IPNet) {
	copied := append([]net.IPNet(nil), nets...)
	trustedProxiesMu.Lock()
	trustedProxies = copied
	trustedProxiesMu.Unlock()
	// Keep the resolved-config cache in step, otherwise the next lookup would
	// re-read the environment and silently undo the call.
	resolved := copied
	trustedProxyConfig.Store(&resolved)
}

// TrustedProxies returns a copy of the current trusted proxy list.
// TrustedProxies returns a copy of the current trusted proxy list, resolving
// the configuration first if it has not been resolved yet.
//
// Resolving here rather than returning whatever happens to be cached matters:
// before lazy resolution was introduced this was populated by init(), so a test
// that saved and restored the value round-tripped the real list. With the list
// resolved on demand, a caller that read it before anything had resolved got an
// empty slice, and restoring that afterwards silently left the limiter trusting
// nothing.
func TrustedProxies() []net.IPNet {
	resolveTrustedProxies()
	trustedProxiesMu.RLock()
	defer trustedProxiesMu.RUnlock()
	return append([]net.IPNet(nil), trustedProxies...)
}

// overBroadProxyPrefixes is the set of prefixes that effectively disable
// forwarded-header filtering. A peer that matches one of them is treated as a
// proxy even when it is an ordinary client, and that client's own address is
// then skipped as a proxy hop — so whatever the client placed to the left of
// it becomes the accepted "client IP". That is the original spoofing hole, so
// an over-broad list is accepted (it may be deliberate) but always logged.
//
// Loopback is exempt: 127.0.0.0/8 and ::1/128 are a single /8 out of
// necessity, and no remote client can hold a loopback source address.
func overBroadProxyPrefix(network net.IPNet) bool {
	ones, _ := network.Mask.Size()
	if ones < 0 {
		return false // non-contiguous mask
	}
	if network.IP.IsLoopback() {
		return false
	}
	if network.IP.To4() != nil {
		return ones <= 8
	}
	return ones <= 16
}

// trustedProxyConfig is resolved from the environment on first use rather than
// in init().
//
// Reading it in init() meant the value was captured before TestMain could clear
// the ambient environment, so an operator (or a CI runner) with
// SAFE_ZONE_TRUSTED_PROXIES exported got it applied to the whole test binary
// with no way to undo: TestMain unset the variable while the package global
// still held 0.0.0.0/0, which is exactly the configuration that makes the
// limiter forgeable. A test that wants to assert hermetic behaviour could not.
var trustedProxyConfig atomic.Pointer[[]net.IPNet]

// resolveTrustedProxies computes the list once and caches it.
func resolveTrustedProxies() []net.IPNet {
	if cached := trustedProxyConfig.Load(); cached != nil {
		return *cached
	}
	return configureTrustedProxies()
}

func configureTrustedProxies() []net.IPNet {
	raw := config.String(TrustedProxiesEnv, DefaultTrustedProxies)
	proxies, err := ParseTrustedProxies(raw)
	if err != nil {
		// Fail closed: a typo must never widen the trust boundary. Falling
		// back to loopback only means forwarded headers are ignored until the
		// operator fixes the value.
		fallback, _ := ParseTrustedProxies(DefaultTrustedProxies)
		logjson.Warn("invalid trusted proxy list; falling back to loopback only", map[string]any{
			"service":  "ratelimit",
			"env":      TrustedProxiesEnv,
			"error":    err.Error(),
			"fallback": DefaultTrustedProxies,
		})
		proxies = fallback
	} else {
		for _, network := range proxies {
			if overBroadProxyPrefix(network) {
				logjson.Warn("trusted proxy prefix is very broad; any client in this range can forge its own client IP", map[string]any{
					"service": "ratelimit",
					"env":     TrustedProxiesEnv,
					"prefix":  network.String(),
				})
			}
		}
	}
	SetTrustedProxies(proxies)
	return proxies
}

func isTrustedProxy(ip string) bool {
	parsedIP := parseHeaderIP(ip)
	if parsedIP == nil {
		return false
	}
	return isTrustedProxyIP(parsedIP)
}

func isTrustedProxyIP(parsedIP net.IP) bool {
	for _, network := range resolveTrustedProxies() {
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

// clientIPFromXForwardedFor returns the rightmost hop that is not itself a
// trusted proxy, which is the real client behind a chain of proxies.
//
// If every hop is a trusted proxy there is no identifiable client, and the
// chain is therefore either malformed or forged. Returning valid[0] here
// would hand back the leftmost entry — the one furthest from the socket and
// the most attacker-controlled value in the header. An empty string tells the
// caller to fall back to the socket address, so this case fails closed.
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
	return ""
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
