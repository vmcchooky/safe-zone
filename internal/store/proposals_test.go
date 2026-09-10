package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAgentProposalLifecycle(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	created, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain:     "Suspicious-Phish.Test",
		Action:     "block",
		Score:      85,
		Confidence: 0.9,
		Reasons:    []string{"tls: self-signed certificate"},
		Evidence:   `{"tls_score":25}`,
	})
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	if created.Domain != "suspicious-phish.test" {
		t.Fatalf("expected normalized domain, got %q", created.Domain)
	}
	if created.Status != AgentProposalPending || created.Actor == "" || created.Scope != "exact" {
		t.Fatalf("expected pending proposal with actor/scope, got %+v", created)
	}
	if created.ExpiresAt == "" {
		t.Fatal("expected default expiry to be set")
	}

	// A repeat proposal refreshes instead of duplicating.
	again, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain: "suspicious-phish.test", Action: "block", Score: 90,
	})
	if err != nil {
		t.Fatalf("refresh proposal: %v", err)
	}
	if again.ID != created.ID || again.Score != 90 {
		t.Fatalf("expected refresh of #%d with score 90, got %+v", created.ID, again)
	}
	pending, err := db.ListAgentProposals(ctx, AgentProposalPending, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected 1 pending proposal, got %d (%v)", len(pending), err)
	}

	reviewed, err := db.ReviewAgentProposal(ctx, created.ID, true, "operator", "confirmed phishing kit")
	if err != nil {
		t.Fatalf("approve proposal: %v", err)
	}
	if reviewed.Status != AgentProposalApproved || reviewed.Reviewer != "operator" {
		t.Fatalf("expected approved proposal, got %+v", reviewed)
	}
	if _, err := db.ReviewAgentProposal(ctx, created.ID, false, "operator", "x"); err == nil {
		t.Fatal("expected re-review of decided proposal to fail")
	}
	pending, err = db.ListAgentProposals(ctx, AgentProposalPending, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected 0 pending after approval, got %d (%v)", len(pending), err)
	}
}

func TestAgentProposalExpiry(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	created, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain:    "stale.test",
		Action:    "block",
		ExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano),
	})
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	if _, err := db.ReviewAgentProposal(ctx, created.ID, true, "operator", "too late"); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired rejection, got %v", err)
	}
	pending, err := db.ListAgentProposals(ctx, AgentProposalPending, 10)
	if err != nil || len(pending) != 0 {
		t.Fatalf("expected expired row hidden from pending, got %d (%v)", len(pending), err)
	}
	expired, err := db.ListAgentProposals(ctx, AgentProposalExpired, 10)
	if err != nil || len(expired) != 1 {
		t.Fatalf("expected 1 expired proposal, got %d (%v)", len(expired), err)
	}
}

func TestHasGroupOverrideForDomain(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	if found, err := db.HasGroupOverrideForDomain(ctx, "a.b.example.com"); err != nil || found {
		t.Fatalf("expected no group override, got %v (%v)", found, err)
	}
	groupID, err := db.CreateGroup(ctx, "reviewers", "", nil, false, true)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.UpsertGroupOverride(ctx, groupID, "example.com", "allow", "group allow"); err != nil {
		t.Fatalf("upsert group override: %v", err)
	}
	if found, err := db.HasGroupOverrideForDomain(ctx, "a.b.example.com"); err != nil || !found {
		t.Fatalf("expected parent group override to match, got %v (%v)", found, err)
	}
	if found, err := db.HasGroupOverrideForDomain(ctx, "other.test"); err != nil || found {
		t.Fatalf("expected no match elsewhere, got %v (%v)", found, err)
	}
}
