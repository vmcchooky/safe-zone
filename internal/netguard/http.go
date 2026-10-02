package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

var ErrBlockedAddress = errors.New("blocked private or local address")

const defaultHTTPTimeout = 30 * time.Second

// NewHTTPClient clones the provided base client and installs a guarded
// transport that rejects localhost/private destinations before dialing them.
func NewHTTPClient(base *http.Client, timeout time.Duration, allowPrivate bool) *http.Client {
	if base == nil {
		base = &http.Client{}
	}

	client := *base
	if client.Timeout <= 0 {
		if timeout <= 0 {
			timeout = defaultHTTPTimeout
		}
		client.Timeout = timeout
	}
	client.Transport = GuardedTransport(base.Transport, allowPrivate)
	return &client
}

// OutboundProxyEnv opts back in to honouring the ambient HTTP proxy variables
// on guarded transports. It exists because an egress-only deployment cannot
// fetch anything without one, not because the proxy is safe.
const OutboundProxyEnv = "SAFE_ZONE_OUTBOUND_PROXY"

// proxyBypassWarned keeps the warning to one line per process. The condition is
// a deployment mistake, not an event, so it must not become log noise on every
// outbound request.
//
// It is an atomic rather than a sync.Once so it can be cleared, which matters
// for correctness and not only for tests: a sync.Once can never be reset, so
// after the opt-in was enabled and then disabled, a second enable would be
// silent. Clearing it when the opt-in is off makes the warning track the
// current configuration.
var proxyBypassWarned atomic.Bool

// GuardedTransport wraps the provided transport with outbound address checks.
//
// The transport's proxy function is cleared first. A cloned
// http.DefaultTransport carries ProxyFromEnvironment, and when HTTP_PROXY or
// HTTPS_PROXY is set the connection goes to the proxy: DialContext is then
// handed the *proxy's* address, so the destination this guard exists to check is
// never the one being validated. The proxy itself is public, so the check
// passes and the guard quietly does nothing. Container deployments routinely
// have these variables set, which is what made the hole reachable in practice.
//
// Clearing it is the fail-closed choice: the guard is what makes outbound
// fetches safe, and an operator who genuinely needs a proxy can say so with
// SAFE_ZONE_OUTBOUND_PROXY=true, which logs a warning that the destination is
// no longer being checked.
func GuardedTransport(base http.RoundTripper, allowPrivate bool) http.RoundTripper {
	if transport, ok := baseTransport(base); ok {
		baseDial := transport.DialContext
		if baseDial == nil {
			dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			baseDial = dialer.DialContext
		}
		transport.Proxy = guardedProxy(transport.Proxy)
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("split host port %q: %w", address, err)
			}
			ips, err := ResolveAllowedIPs(ctx, host, allowPrivate)
			if err != nil {
				return nil, err
			}
			return baseDial(ctx, network, net.JoinHostPort(ips[0].String(), port))
		}
		transport.DialTLSContext = nil
		return transport
	}

	// A base that is not an *http.Transport cannot be guarded: the address
	// check only works by rewriting DialContext, and a custom RoundTripper owns
	// its own connection policy — including whether it proxies. Validating the
	// URL and resolving the host below would look like protection while the
	// connection still went wherever the base decided, which is exactly the
	// proxy hole this function exists to close.
	//
	// So this fails closed. Every caller in the tree passes nil or an
	// *http.Transport, so nothing legitimate is refused today, and the failure
	// is loud at the point of wiring rather than silent at the point of fetch.
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("%w: guarded transport requires a base *http.Transport, got %T; "+
			"a custom RoundTripper cannot be address-checked because it controls its own connections",
			ErrUnguardableTransport, base)
	})
}

// ErrUnguardableTransport reports a base RoundTripper netguard cannot install
// its address check into.
var ErrUnguardableTransport = errors.New("cannot guard transport")

// ValidateURL parses and validates a URL that will be used for outbound HTTP.
func ValidateURL(raw string, allowPrivate bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}
	if err := ValidateParsedURL(parsed, allowPrivate); err != nil {
		return nil, err
	}
	return parsed, nil
}

// ValidateParsedURL validates URL scheme/host and rejects obvious local targets.
func ValidateParsedURL(parsed *url.URL, allowPrivate bool) error {
	if parsed == nil {
		return errors.New("missing url")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported url scheme %q", parsed.Scheme)
	}
	host := normalizeHost(parsed.Hostname())
	if host == "" {
		return errors.New("missing url host")
	}
	if allowPrivate {
		return nil
	}
	if isLocalHostname(host) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	if ip := net.ParseIP(host); ip != nil && IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}
	return nil
}

// ResolveAllowedIPs resolves a host and rejects any blocked address.
func ResolveAllowedIPs(ctx context.Context, host string, allowPrivate bool) ([]net.IP, error) {
	host = normalizeHost(host)
	if host == "" {
		return nil, errors.New("missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if !allowPrivate && IsBlockedIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedAddress, host)
		}
		return []net.IP{ip}, nil
	}
	if !allowPrivate && isLocalHostname(host) {
		return nil, fmt.Errorf("%w: %s", ErrBlockedAddress, host)
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve host %q: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve host %q: no addresses", host)
	}
	if !allowPrivate {
		for _, ip := range ips {
			if IsBlockedIP(ip) {
				return nil, fmt.Errorf("%w: %s", ErrBlockedAddress, host)
			}
		}
	}
	return ips, nil
}

// nonRoutableV4 lists the IPv4 ranges that are not globally routable and that
// net.IP's own predicates do not cover.
//
//	0.0.0.0/8        "this network". Only 0.0.0.0 is IsUnspecified, but Linux
//	                 routes the whole /8 to loopback, so http://0.0.0.1/ is a
//	                 request to localhost.
//	192.0.0.0/24     IETF protocol assignments.
//	198.18.0.0/15    benchmarking (RFC 2544).
//	240.0.0.0/4      reserved, including 255.255.255.255.
//
// Documentation ranges (RFC 5737 TEST-NET, 192.0.2.0/24 and friends) are
// deliberately absent: they are widely used in fixtures and examples, and
// blocking them would break test suites. They are also not routable, so a fetch
// to one fails on its own. What blocking them does add is refusing to use a
// documentation address as an SSRF target in a test harness.
var nonRoutableV4 = mustParseCIDRs(
	"0.0.0.0/8",
	"192.0.0.0/24",
	"198.18.0.0/15",
	"240.0.0.0/4",
)

// nonRoutableV6 lists the IPv6 ranges that either carry no routable meaning or
// tunnel an IPv4 destination past the IPv4 checks.
//
//	::/96            IPv4-compatible IPv6, deprecated; a mapped address here is
//	                 a way to write 127.0.0.1 without To4() recognising it.
//	2001::/32        Teredo, which wraps an IPv4 server and client address in
//	                 the prefix and port fields.
//	2002::/16        6to4, which embeds the IPv4 destination directly in the
//	                 next 32 bits, so 2002:7f00:0001::1 is 127.0.0.1.
//	64:ff9b::/96     NAT64 well-known prefix, used by IPv6-only networks.
//
// The first two are the interesting ones: without them
// IsBlockedIP(127.0.0.1) is true while IsBlockedIP(2002:7f00:0001::1) — the
// same host — is false, and 2002:a9fe:a9fe::1 is 6to4 for 169.254.169.254,
// the cloud metadata endpoint that motivated the guard at all.
//
// These are not speculative: 6to4 relay deprecation is only partial, and
// Teredo is still reachable. Exploitability is lower than for a plain private
// IPv4 literal because the transition mechanism has to be up on the path, but
// the whole point of one shared predicate is that it does not have a hole
// shaped like "forgot the transition ranges".
var nonRoutableV6 = mustParseCIDRs(
	"::/96",
	"64:ff9b::/96",
	"2001::/32",
	"2002::/16",
)

// IsBlockedIP reports whether an address is not a routable public destination:
// loopback, private, link-local, multicast, CGNAT, unspecified, or inside one
// of the non-routable ranges above.
//
// This is the single definition used by every outbound fetch in the codebase.
// Two near-identical copies of it lived in the osint and tlsinspect packages
// and had drifted: the osint copy omitted CGNAT, and the tlsinspect copy omitted
// multicast. A source resolving into 100.64.0.0/10 — the carrier-NAT and
// Tailscale range — was therefore accepted where netguard would have rejected
// it. Callers should use this rather than re-deriving the rule.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || IsCGNAT(ip) {
		return true
	}
	// Compare against the 4-byte form so an IPv4-mapped IPv6 address is judged
	// by its IPv4 value rather than escaping the check.
	if ip4 := ip.To4(); ip4 != nil {
		for _, network := range nonRoutableV4 {
			if network.Contains(ip4) {
				return true
			}
		}
		return false
	}
	for _, network := range nonRoutableV6 {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func mustParseCIDRs(cidrs ...string) []net.IPNet {
	parsed := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// The literals above are compile-time constants, so a failure here
			// is a programming error rather than operator input.
			panic("netguard: invalid built-in CIDR " + cidr + ": " + err.Error())
		}
		parsed = append(parsed, *network)
	}
	return parsed
}

// IsCGNAT reports whether the address falls into the RFC 6598 shared
// address space 100.64.0.0/10. These addresses are not globally routable
// and must never be reachable through outbound fetches.
func IsCGNAT(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 100 && ip4[1] >= 64 && ip4[1] <= 127
}

// CheckRedirect is an http.Client redirect policy that validates every
// redirect hop against the outbound policy. A fetch started from an
// allowed URL is not allowed to be redirected into loopback, private,
// link-local, CGNAT or otherwise blocked address space, or to change to
// a non-HTTP scheme. Returning an error makes the client stop following
// redirects and surface the error to the caller instead of silently
// returning the redirect response.
func CheckRedirect(req *http.Request, via []*http.Request) error {
	return RedirectPolicy(false)(req, via)
}

// RedirectPolicy returns the same outbound redirect policy parameterized
// by private-source allowance, so services that legitimately fetch from
// private test or intranet hosts (explicit opt-in) keep working redirects
// while metadata/link-local targets stay blocked unconditionally.
func RedirectPolicy(allowPrivate bool) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		if err := ValidateParsedURL(req.URL, allowPrivate); err != nil {
			return fmt.Errorf("blocked redirect: %w", err)
		}
		if _, err := ResolveAllowedIPs(req.Context(), req.URL.Hostname(), allowPrivate); err != nil {
			return fmt.Errorf("blocked redirect: %w", err)
		}
		return nil
	}
}

// RedirectPolicyHTTPS is RedirectPolicy with scheme-downgrade protection:
// every hop must stay on https. It exists for fetches whose initial URL
// was already gated to https (threat feeds): without it, a 302 to a
// plain-http URL would smuggle MITM-able bytes past a string-prefix gate.
// Downgrade protection is hop-absolute, not relative to the start URL, so
// callers that legitimately begin on http keep using RedirectPolicy.
func RedirectPolicyHTTPS(allowPrivate bool) func(*http.Request, []*http.Request) error {
	base := RedirectPolicy(allowPrivate)
	return func(req *http.Request, via []*http.Request) error {
		if !strings.EqualFold(req.URL.Scheme, "https") {
			return fmt.Errorf("blocked redirect: https-only fetch must not downgrade to %q", req.URL.Scheme)
		}
		return base(req, via)
	}
}

// OutboundProxyEnabled reports whether the operator has switched the address
// guard off in favour of an ambient proxy. Exposed so the decision can be
// published as service state rather than inferred from a log line: with a proxy
// configured, netguard validates the proxy's address instead of the
// destination's, so every guarded fetch runs unchecked.
func OutboundProxyEnabled() bool {
	return config.Bool(OutboundProxyEnv, false)
}

// guardedProxy decides what proxy function a guarded transport keeps. The
// returned value is nil unless the operator explicitly opts in, so the
// destination — not a proxy — is what DialContext validates.
func guardedProxy(inherited func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	if !config.Bool(OutboundProxyEnv, false) {
		// Opt-in is off, so there is nothing to warn about. Clearing the flag
		// here means a later re-enable warns again rather than being swallowed
		// by a latch left over from a previous configuration.
		proxyBypassWarned.Store(false)
		return nil
	}
	proxy := inherited
	if proxy == nil {
		proxy = http.ProxyFromEnvironment
	}
	if proxy != nil && proxyBypassWarned.CompareAndSwap(false, true) {
		logjson.Warn("outbound HTTP proxy enabled; the destination address is no longer checked by netguard", map[string]any{
			"service": "netguard",
			"env":     OutboundProxyEnv,
			"risk":    "a proxy can reach addresses the address guard would reject, including loopback and link-local metadata endpoints",
		})
	}
	return proxy
}

func baseTransport(base http.RoundTripper) (*http.Transport, bool) {
	if base == nil {
		base = http.DefaultTransport
	}
	transport, ok := base.(*http.Transport)
	if !ok {
		return nil, false
	}
	return transport.Clone(), true
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return strings.Trim(host, "[]")
}

func isLocalHostname(host string) bool {
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
