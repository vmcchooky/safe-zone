package store

import (
	"testing"
	"time"
)

// P-2: decided reports age out with retention; pending reports are never
// auto-deleted (they are the operator review queue).
func TestCleanupPrunesDecidedReportsOnly(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()

	old := time.Now().AddDate(0, 0, -31).UTC().Format("2006-01-02 15:04:05")
	seed := []struct {
		domain, status, created string
	}{
		{"old-resolved.test", "resolved", old},
		{"old-rejected.test", "rejected", old},
		{"old-pending.test", "pending", old},
		{"new-resolved.test", "resolved", time.Now().UTC().Format("2006-01-02 15:04:05")},
	}
	for _, row := range seed {
		if _, err := db.db.Exec(
			`INSERT INTO block_reports (domain, status, created_at) VALUES (?, ?, ?)`,
			row.domain, row.status, row.created); err != nil {
			t.Fatalf("seed report: %v", err)
		}
	}

	db.cleanup()

	remaining := make(map[string]string)
	rows, err := db.db.Query(`SELECT domain, status FROM block_reports`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var domain, status string
		if err := rows.Scan(&domain, &status); err != nil {
			t.Fatal(err)
		}
		remaining[domain] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 2 || remaining["old-pending.test"] != "pending" || remaining["new-resolved.test"] != "resolved" {
		t.Fatalf("expected only old-pending + new-resolved to survive, got %v", remaining)
	}
}

// Decided proposals and audit events used to accumulate forever. Proposals are
// reviewable evidence, so they age out only after a decision or after their TTL
// lapses; the review queue itself must survive. Audit events are kept longer so
// an approval can still be explained after its proposal row is gone.
func TestCleanupPrunesDecidedProposalsAndOldAuditEvents(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	db.proposalRetentionDays = 10
	db.auditRetentionDays = 20

	now := time.Now().UTC()
	stamp := func(daysAgo int) string {
		return now.AddDate(0, 0, -daysAgo).Format("2006-01-02 15:04:05")
	}
	seedProposal := func(domain, status, expiresAt, updatedAt string) {
		t.Helper()
		if _, err := db.db.Exec(
			`INSERT INTO agent_proposals (domain, action, status, expires_at, created_at, updated_at)
			 VALUES (?, 'block', ?, ?, ?, ?)`,
			domain, status, expiresAt, updatedAt, updatedAt); err != nil {
			t.Fatalf("seed proposal %s: %v", domain, err)
		}
	}
	seedProposal("old-approved.test", AgentProposalApproved, stamp(11), stamp(11))
	seedProposal("old-rejected.test", AgentProposalRejected, stamp(11), stamp(11))
	// expires_at is stored as RFC3339Nano by CreateAgentProposal; seed the
	// lapsed row in that format so retention is exercised against production
	// data rather than only the SQLite space format.
	seedProposal("lapsed-pending.test", AgentProposalPending, now.AddDate(0, 0, -11).UTC().Format(time.RFC3339Nano), stamp(11))
	seedProposal("fresh-pending.test", AgentProposalPending, now.AddDate(0, 0, 7).Format(time.RFC3339Nano), stamp(11))
	seedProposal("recent-approved.test", AgentProposalApproved, stamp(5), stamp(5))

	for _, event := range []struct {
		domain string
		days   int
	}{
		{"old-event.test", 21},
		{"middle-event.test", 15},
		{"new-event.test", 0},
	} {
		if _, err := db.db.Exec(
			`INSERT INTO agent_audit_log (task_name, event_type, domain, details, created_at)
			 VALUES ('audit', 'test_event', ?, '{}', ?)`,
			event.domain, stamp(event.days)); err != nil {
			t.Fatalf("seed audit event %s: %v", event.domain, err)
		}
	}

	db.cleanup()

	proposals := map[string]bool{}
	rows, err := db.db.Query(`SELECT domain FROM agent_proposals`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			t.Fatal(err)
		}
		proposals[domain] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(proposals) != 2 || !proposals["fresh-pending.test"] || !proposals["recent-approved.test"] {
		t.Fatalf("proposal retention kept %v, want only fresh-pending + recent-approved", proposals)
	}

	events := map[string]bool{}
	rows, err = db.db.Query(`SELECT domain FROM agent_audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			t.Fatal(err)
		}
		events[domain] = true
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !events["middle-event.test"] || !events["new-event.test"] {
		t.Fatalf("audit retention kept %v, want only middle-event + new-event", events)
	}
}

func TestAgentRetentionEnvironment(t *testing.T) {
	t.Setenv("SAFE_ZONE_AGENT_PROPOSAL_RETENTION_DAYS", "45")
	t.Setenv("SAFE_ZONE_AGENT_AUDIT_RETENTION_DAYS", "garbage")
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if db.proposalRetentionDays != 45 {
		t.Fatalf("proposal retention = %d, want 45 from the environment", db.proposalRetentionDays)
	}
	if db.auditRetentionDays != DefaultAgentAuditRetentionDays {
		t.Fatalf("audit retention = %d, want the default %d for an invalid value",
			db.auditRetentionDays, DefaultAgentAuditRetentionDays)
	}

	t.Setenv("SAFE_ZONE_AGENT_PROPOSAL_RETENTION_DAYS", "99999")
	second, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("create second test store: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.proposalRetentionDays != MaxRetentionDays {
		t.Fatalf("proposal retention = %d, want the ceiling %d", second.proposalRetentionDays, MaxRetentionDays)
	}
}
