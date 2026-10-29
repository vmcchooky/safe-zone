package doh

import (
	"context"
	"errors"
	"testing"

	"safe-zone/internal/netguard"
)

// TestForwardRejectsBlockedUpstreamBeforeAnyDial pins the pool-level guard:
// every endpoint of the upstream pool is validated per exchange, so a pool
// configured entirely with private/metadata endpoints fails closed before
// any dial happens (no network access, no fallback to an unguarded client).
// A mixed pool is deliberately not tested here: its healthy endpoint would
// dial for real, which the offline test contract forbids.
func TestForwardRejectsBlockedUpstreamBeforeAnyDial(t *testing.T) {
	pool := NewUpstreamResolver("http://127.0.0.1:5335/dns-query,http://169.254.169.254/dns-query", nil)
	if got := len(pool.endpoints); got != 2 {
		t.Fatalf("pool has %d endpoints, want 2 (the guard must not drop blocked URLs silently)", got)
	}

	_, _, err := pool.Forward(context.Background(), []byte{0x00, 0x00})
	if err == nil {
		t.Fatal("Forward succeeded against a fully private upstream pool")
	}
	if !errors.Is(err, netguard.ErrBlockedAddress) {
		t.Fatalf("error = %v, want it to wrap netguard.ErrBlockedAddress", err)
	}
}

// TestExchangeRejectsNilClient closes the validate-then-dial seam where a
// nil client used to fall back to http.DefaultClient: pre-flight validation
// passes for a public URL, but the subsequent dial would run without the
// guarded transport, opening a rebinding window. Failing closed keeps every
// caller honest about which client performs the dial.
func TestExchangeRejectsNilClient(t *testing.T) {
	_, err := Exchange(context.Background(), nil, "https://cloudflare-dns.com/dns-query", []byte{0x00, 0x00})
	if err == nil {
		t.Fatal("Exchange accepted a nil client; it must fail closed")
	}
}
