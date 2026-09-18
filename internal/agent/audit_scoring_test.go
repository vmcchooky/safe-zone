package agent

import (
	"context"
	"testing"

	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// The byteoversea production shape (expired + mismatched CDN cert, newish
// domain, real-scanner AdvisoryScores) must not manufacture a MALICIOUS
// proposal from metadata alone.
func weakMetadataEnrichment(_ *testing.T) func(context.Context, string) (tlsinspect.Result, whois.Result) {
	return func(context.Context, string) (tlsinspect.Result, whois.Result) {
		return tlsinspect.Result{
				HasTLS: true, Expired: true, Score: 50, AdvisoryScore: 30,
				Reasons: []string{"tls: certificate expired", "tls: certificate name does not match domain"},
			}, whois.Result{
				Found: true, DomainAgeDays: 3, Score: 25,
				Reasons: []string{"whois: domain registered < 7 days ago"},
			}
	}
}

func TestAgentScoreAdvisoryCap(t *testing.T) {
	cases := []struct {
		name  string
		tls   tlsinspect.Result
		whois whois.Result
		want  int
	}{
		{"weak only", tlsinspect.Result{Score: 45, AdvisoryScore: 45}, whois.Result{}, 10},
		{"legacy unscored keeps weight", tlsinspect.Result{Score: 45}, whois.Result{Score: 25}, 70},
		{"production byteoversea shape", tlsinspect.Result{Score: 50, AdvisoryScore: 30}, whois.Result{Score: 25}, 55},
		{"all strong still flags", tlsinspect.Result{Score: 70, AdvisoryScore: 30}, whois.Result{Score: 25}, 75},
	}
	for _, tc := range cases {
		if got := agentScore(tc.tls, tc.whois); got != tc.want {
			t.Errorf("%s: agentScore = %d; want %d", tc.name, got, tc.want)
		}
	}
}

func TestAuditDomainWeakMetadataStaysReviewed(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{ConfidenceThreshold: 0.01})
	task.enrich = weakMetadataEnrichment(t)

	action, err := task.auditDomain(context.Background(), "cdn-edge-example.test")
	if err != nil {
		t.Fatalf("audit domain: %v", err)
	}
	if action != "reviewed" {
		t.Fatalf("metadata-only signals must not propose, got %q", action)
	}
	pending, err := db.ListAgentProposals(context.Background(), store.AgentProposalPending, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected no proposals from weak metadata, got %d", len(pending))
	}
}
