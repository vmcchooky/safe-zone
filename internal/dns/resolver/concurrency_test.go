package resolver

import (
	"context"
	"strings"
	"testing"

	"safe-zone/internal/dns/doh"
)

// Saturating the global in-flight budget fails closed with SERVFAIL
// instead of queuing unbounded evaluation work.
func TestResolveQueryConcurrencyLimitFailsClosed(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, _ := newPipelineResolver(t, upstreamURL, upstreamClient)

	r.inflight.Add(int64(DefaultMaxConcurrentQueries))
	_, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "any.test"), doh.ClientInfo{IP: "192.168.1.10"})
	r.inflight.Add(-int64(DefaultMaxConcurrentQueries))
	if err == nil || !strings.Contains(err.Error(), "too many concurrent") {
		t.Fatalf("expected concurrency fail-closed error, got %v", err)
	}
}

// Normal traffic under the cap is unaffected.
func TestResolveQueryUnderConcurrencyCap(t *testing.T) {
	upstream := echoUpstream(t)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, _ := newPipelineResolver(t, upstreamURL, upstreamClient)

	if _, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "example.com"), doh.ClientInfo{IP: "192.168.1.10"}); err != nil {
		t.Fatalf("query under cap must succeed, got %v", err)
	}
	if n := r.inflight.Load(); n != 0 {
		t.Fatalf("inflight counter must return to zero, got %d", n)
	}
}
