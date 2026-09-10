package agent

import (
	"context"
	"testing"

	"safe-zone/internal/store"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// hostileEnrichment returns fixed malicious-grade signals without network.
func hostileEnrichment(t *testing.T) func(context.Context, string) (tlsinspect.Result, whois.Result) {
	t.Helper()
	return func(context.Context, string) (tlsinspect.Result, whois.Result) {
		return tlsinspect.Result{
				HasTLS: true, SelfSigned: true, Score: 45,
				Reasons: []string{"tls: self-signed certificate", "tls: certificate name does not match domain"},
			}, whois.Result{
				Found: true, DomainAgeDays: 3, Score: 25,
				Reasons: []string{"whois: domain registered < 7 days ago"},
			}
	}
}

// By default the audit must not write overrides: a malicious finding
// becomes a reviewable proposal carrying evidence, actor and scope.
func TestAuditDomainContainedByDefault(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{ConfidenceThreshold: 0.01})
	task.enrich = hostileEnrichment(t)

	action, err := task.auditDomain(context.Background(), "agent-candidate.test")
	if err != nil {
		t.Fatalf("audit domain: %v", err)
	}
	if action != "proposed" {
		t.Fatalf("expected proposed action, got %q", action)
	}
	if override, _ := db.GetOverride(context.Background(), "agent-candidate.test"); override != nil {
		t.Fatalf("contained audit must not write overrides, got %+v", override)
	}
	pending, err := db.ListAgentProposals(context.Background(), store.AgentProposalPending, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected 1 pending proposal, got %d (%v)", len(pending), err)
	}
	p := pending[0]
	if p.Action != "block" || p.Actor != "agent:audit" || p.Scope != "exact" {
		t.Fatalf("proposal must carry action/actor/scope, got %+v", p)
	}
	if p.Score < 70 || len(p.Reasons) == 0 || p.Evidence == "" || p.ExpiresAt == "" {
		t.Fatalf("proposal must carry score/evidence/expiry, got %+v", p)
	}
}

// Explicit opt-in preserves the legacy direct-to-override path.
func TestAuditDomainAutoEnforceOptIn(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{ConfidenceThreshold: 0.01, AutoEnforce: true})
	task.enrich = hostileEnrichment(t)

	action, err := task.auditDomain(context.Background(), "legacy-candidate.test")
	if err != nil {
		t.Fatalf("audit domain: %v", err)
	}
	if action != "blocked" {
		t.Fatalf("expected blocked action under opt-in, got %q", action)
	}
	override, err := db.GetOverride(context.Background(), "legacy-candidate.test")
	if err != nil || override == nil || override.Action != "block" {
		t.Fatalf("expected block override under opt-in, got %+v (%v)", override, err)
	}
	pending, err := db.ListAgentProposals(context.Background(), store.AgentProposalPending, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected no proposals under opt-in, got %d (%v)", len(pending), err)
	}
}

// Group-scoped policy the agent cannot see must still stop it, even in
// proposal mode.
func TestAuditDomainSkipsGroupOverride(t *testing.T) {
	db := newTestStore(t)
	groupID, err := db.CreateGroup(context.Background(), "reviewers", "", nil, false, true)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.UpsertGroupOverride(context.Background(), groupID, "grouped.test", "allow", "group allow"); err != nil {
		t.Fatalf("upsert group override: %v", err)
	}
	task := NewAuditTask(db, nil, nil, AuditConfig{ConfidenceThreshold: 0.01})
	task.enrich = hostileEnrichment(t)

	action, err := task.auditDomain(context.Background(), "grouped.test")
	if err != nil {
		t.Fatalf("audit domain: %v", err)
	}
	if action != "skipped" {
		t.Fatalf("expected skipped for group-overridden domain, got %q", action)
	}
	pending, err := db.ListAgentProposals(context.Background(), store.AgentProposalPending, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected no proposal against group policy, got %d (%v)", len(pending), err)
	}
}
