package doh

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime"
	"net/http"

	"safe-zone/internal/netguard"
)

// Exchange sends one DNS query to an upstream DoH endpoint (RFC 8484
// section 4.1 client role) and returns the raw DNS response wire message.
// The exchange always uses POST: it is immune to intermediary HTTP caches
// and avoids leaking the question into URLs.
//
// Both the configured upstream URL and every redirect hop are validated
// against the shared outbound policy (netguard), so a compromised or
// hostile upstream cannot redirect the exchange into loopback, private,
// link-local, CGNAT or otherwise blocked address space. A redirect to a
// disallowed target fails the exchange with an explicit error instead of
// being followed or returned as success.
func Exchange(ctx context.Context, client *http.Client, upstreamURL string, wire []byte) ([]byte, error) {
	parsed, err := netguard.ValidateURL(upstreamURL, false)
	if err != nil {
		return nil, fmt.Errorf("blocked upstream DoH URL: %w", err)
	}
	if _, err := netguard.ResolveAllowedIPs(ctx, parsed.Hostname(), false); err != nil {
		return nil, fmt.Errorf("blocked upstream DoH host: %w", err)
	}
	if client == nil {
		client = http.DefaultClient
	}
	// Shallow-copy so the redirect policy is enforced without mutating a
	// client that may be shared with the caller.
	guarded := *client
	guarded.CheckRedirect = netguard.CheckRedirect
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", ContentTypeDNSMessage)
	req.Header.Set("Content-Type", ContentTypeDNSMessage)

	// #nosec G107 G704 -- URL is validated against the outbound policy above,
	// and every redirect hop is validated by guarded.CheckRedirect.
	resp, err := guarded.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("upstream returned HTTP %d", resp.StatusCode)
	}

	// A 200 carrying anything other than a DNS message (captive portal HTML,
	// proxy error pages) must fail the exchange instead of reaching Unpack.
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType != ContentTypeDNSMessage {
		return nil, fmt.Errorf("upstream returned unexpected Content-Type %q", resp.Header.Get("Content-Type"))
	}

	// Read one byte past the limit so truncated-but-full reads are
	// distinguishable from oversized responses.
	response, err := io.ReadAll(io.LimitReader(resp.Body, MaxDNSMessageSize+1))
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, fmt.Errorf("upstream returned an empty DNS message")
	}
	if len(response) > MaxDNSMessageSize {
		return nil, fmt.Errorf("upstream DNS message exceeds %d bytes", MaxDNSMessageSize)
	}
	return response, nil
}
