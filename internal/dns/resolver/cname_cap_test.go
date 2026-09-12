package resolver

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"safe-zone/internal/dns/doh"
)

// cnameFloodUpstream answers every query with count CNAME records pointing
// at chained allow-targets, except the blocked position which points at a
// domain the test overrides to block.
func cnameFloodUpstream(t *testing.T, count int, blockedAt int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := readAllLimited(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		query := new(dns.Msg)
		if err := query.Unpack(body); err != nil {
			http.Error(w, "invalid dns message", http.StatusBadRequest)
			return
		}
		response := new(dns.Msg)
		response.SetReply(query)
		for i := 1; i <= count; i++ {
			target := fmt.Sprintf("allow-%d.flood.example.", i)
			if i == blockedAt {
				target = "blocked-target.flood.example."
			}
			response.Answer = append(response.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: testAnswerTTL},
				Target: target,
			})
		}
		wire, err := response.Pack()
		if err != nil {
			t.Errorf("pack flood response: %v", err)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
}

// A blocked target inside the cap still sinkholes (existing behavior).
func TestResolveQueryUncloaksBlockedCNAMETargetWithinCap(t *testing.T) {
	upstream := cnameFloodUpstream(t, 3, 2)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolver(t, upstreamURL, upstreamClient)
	if err := storeDB.UpsertOverride(context.Background(), "blocked-target.flood.example", "block", "test"); err != nil {
		t.Fatal(err)
	}

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "entry.flood.example"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	aRecord, ok := response.Answer[0].(*dns.A)
	if !ok || aRecord.A.String() != testBlockPageIP {
		t.Fatalf("expected sinkhole for in-cap blocked target, got %#v", response.Answer)
	}
}

// More CNAME targets than the cap fails closed (SERVFAIL upstream path)
// instead of silently allowing the unchecked tail.
func TestResolveQueryCNAMEFloodFailsClosed(t *testing.T) {
	upstream := cnameFloodUpstream(t, maxCNAMEPolicyChecks+3, maxCNAMEPolicyChecks+2)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, storeDB, _ := newPipelineResolver(t, upstreamURL, upstreamClient)
	if err := storeDB.UpsertOverride(context.Background(), "blocked-target.flood.example", "block", "test"); err != nil {
		t.Fatal(err)
	}

	if _, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "entry.flood.example"), doh.ClientInfo{IP: "192.168.1.10"}); err == nil ||
		!strings.Contains(err.Error(), "cname policy check limit") {
		t.Fatalf("expected fail-closed limit error, got %v", err)
	}
}

// Exactly at the cap still evaluates (no off-by-one fail-closed).
func TestResolveQueryCNAMEAtCapEvaluates(t *testing.T) {
	upstream := cnameFloodUpstream(t, maxCNAMEPolicyChecks, 0)
	defer upstream.Close()
	upstreamURL, upstreamClient := policyUpstream(t, upstream)
	r, _, _ := newPipelineResolver(t, upstreamURL, upstreamClient)

	response, err := r.ResolveQuery(context.Background(), testPipelineQuery(t, "entry.flood.example"), doh.ClientInfo{IP: "192.168.1.10"})
	if err != nil {
		t.Fatalf("at-cap chain must forward, got error %v", err)
	}
	if len(response.Answer) != maxCNAMEPolicyChecks {
		t.Fatalf("expected %d forwarded answers, got %d", maxCNAMEPolicyChecks, len(response.Answer))
	}
}
