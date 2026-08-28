package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// GuardedTransport wraps the provided transport with outbound address checks.
func GuardedTransport(base http.RoundTripper, allowPrivate bool) http.RoundTripper {
	if transport, ok := baseTransport(base); ok {
		baseDial := transport.DialContext
		if baseDial == nil {
			dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
			baseDial = dialer.DialContext
		}
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

	if base == nil {
		base = http.DefaultTransport
	}
	return roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		if err := ValidateParsedURL(req.URL, allowPrivate); err != nil {
			return nil, err
		}
		if _, err := ResolveAllowedIPs(req.Context(), req.URL.Hostname(), allowPrivate); err != nil {
			return nil, err
		}
		return base.RoundTrip(req)
	})
}

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

// IsBlockedIP reports whether an address is loopback, private, link-local,
// carrier-grade NAT, or otherwise not a routable public destination.
func IsBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || IsCGNAT(ip)
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
	if len(via) >= 10 {
		return fmt.Errorf("stopped after 10 redirects")
	}
	if err := ValidateParsedURL(req.URL, false); err != nil {
		return fmt.Errorf("blocked redirect: %w", err)
	}
	if _, err := ResolveAllowedIPs(req.Context(), req.URL.Hostname(), false); err != nil {
		return fmt.Errorf("blocked redirect: %w", err)
	}
	return nil
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
