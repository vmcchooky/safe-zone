package store

import (
	"context"
	"errors"
	"strconv"
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

func TestApprovingAProposalAppliesTheOverride(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	created, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain: "approved-atomic.test", Action: "block", Score: 90, Confidence: 0.9,
	})
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	reviewed, err := db.ReviewAgentProposal(ctx, created.ID, true, "alice", "confirmed phishing kit")
	if err != nil {
		t.Fatalf("approve proposal: %v", err)
	}
	if reviewed.Status != AgentProposalApproved {
		t.Fatalf("status = %q, want approved", reviewed.Status)
	}

	override, err := db.GetOverride(ctx, "approved-atomic.test")
	if err != nil {
		t.Fatalf("read applied override: %v", err)
	}
	if override == nil || override.Action != "block" {
		t.Fatalf("approval did not apply a block override: %+v", override)
	}
	for _, want := range []string{"approved agent proposal #" + strconv.FormatInt(created.ID, 10), "confirmed phishing kit", "reviewer: alice"} {
		if !strings.Contains(override.Reason, want) {
			t.Fatalf("override reason %q does not contain %q", override.Reason, want)
		}
	}
}

func TestApprovalRefusesAConflictingGroupOverride(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	created, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain: "sub.conflict.test", Action: "block", Score: 90, Confidence: 0.9,
	})
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	groupID, err := db.CreateGroup(ctx, "family", "", nil, false, true)
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.UpsertGroupOverride(ctx, groupID, "conflict.test", "allow", "family allow"); err != nil {
		t.Fatalf("upsert group override: %v", err)
	}

	_, err = db.ReviewAgentProposal(ctx, created.ID, true, "alice", "late approval")
	if !errors.Is(err, ErrProposalGroupOverride) {
		t.Fatalf("approval over group policy = %v, want ErrProposalGroupOverride", err)
	}
	pending, err := db.GetAgentProposal(ctx, created.ID)
	if err != nil {
		t.Fatalf("re-read proposal: %v", err)
	}
	if pending.Status != AgentProposalPending {
		t.Fatalf("status = %q after refused approval, want pending", pending.Status)
	}
	if override, err := db.GetOverride(ctx, "sub.conflict.test"); err != nil || override != nil {
		t.Fatalf("refused approval wrote an override: %+v (%v)", override, err)
	}

	// Rejection is still allowed: group policy blocks enforcement, not triage.
	if _, err := db.ReviewAgentProposal(ctx, created.ID, false, "alice", "group policy wins"); err != nil {
		t.Fatalf("reject proposal with group override: %v", err)
	}
}

func TestApprovalFailureLeavesTheProposalPendingAndRetryable(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	ctx := context.Background()

	created, err := db.CreateAgentProposal(ctx, AgentProposal{
		Domain: "retry-override.test", Action: "block", Score: 90, Confidence: 0.9,
	})
	if err != nil {
		t.Fatalf("create proposal: %v", err)
	}
	// Inject the old failure mode: the override write fails after the proposal
	// transition would have been committed by the previous two-step handler.
	if _, err := db.db.ExecContext(ctx, `
		CREATE TRIGGER fail_override_insert BEFORE INSERT ON local_overrides
		WHEN NEW.domain = 'retry-override.test'
		BEGIN
			SELECT RAISE(ABORT, 'injected override failure');
		END`); err != nil {
		t.Fatalf("create failure trigger: %v", err)
	}

	if _, err := db.ReviewAgentProposal(ctx, created.ID, true, "alice", "first attempt"); err == nil {
		t.Fatal("expected the injected override failure to abort the approval")
	}
	pending, err := db.GetAgentProposal(ctx, created.ID)
	if err != nil {
		t.Fatalf("re-read proposal: %v", err)
	}
	if pending.Status != AgentProposalPending {
		t.Fatalf("status = %q after failed approval, want pending", pending.Status)
	}
	if override, err := db.GetOverride(ctx, "retry-override.test"); err != nil || override != nil {
		t.Fatalf("failed approval wrote an override: %+v (%v)", override, err)
	}

	if _, err := db.db.ExecContext(ctx, `DROP TRIGGER fail_override_insert`); err != nil {
		t.Fatalf("drop failure trigger: %v", err)
	}
	reviewed, err := db.ReviewAgentProposal(ctx, created.ID, true, "alice", "retry")
	if err != nil {
		t.Fatalf("retry after the failure was not accepted: %v", err)
	}
	if reviewed.Status != AgentProposalApproved {
		t.Fatalf("status = %q after retry, want approved", reviewed.Status)
	}
	if override, err := db.GetOverride(ctx, "retry-override.test"); err != nil || override == nil {
		t.Fatalf("retry did not apply the override: %+v (%v)", override, err)
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
