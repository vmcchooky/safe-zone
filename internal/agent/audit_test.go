package agent

import (
	"context"
	"testing"
	"time"

	"safe-zone/internal/store"
)

func newTestStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.New(":memory:", 30)
	if err != nil {
		t.Fatalf("create test store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedSuspiciousDomains(t *testing.T, db *store.DB, domain string, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		db.RecordAnalysis(store.TelemetryEntry{
			Domain:     domain,
			Verdict:    "SUSPICIOUS",
			Score:      55,
			Confidence: 0.5,
			Reasons:    []string{"phishing keyword pattern"},
			Source:     "lexical",
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	// Give async writer time to flush all entries.
	time.Sleep(500 * time.Millisecond)
}

func TestAuditTaskName(t *testing.T) {
	task := NewAuditTask(nil, nil, nil, AuditConfig{})
	if task.Name() != "audit" {
		t.Errorf("expected name 'audit', got %q", task.Name())
	}
}

func TestAuditTaskNilStore(t *testing.T) {
	task := NewAuditTask(nil, nil, nil, AuditConfig{})
	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error for nil store, got %v", err)
	}
}

func TestAuditTaskNoDomains(t *testing.T) {
	db := newTestStore(t)
	task := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences: 3,
		MaxPerCycle:    10,
	})

	err := task.Run(context.Background())
	if err != nil {
		t.Errorf("expected nil error with no suspicious domains, got %v", err)
	}
}

func TestAuditTaskSkipsOverriddenDomain(t *testing.T) {
	db := newTestStore(t)

	// Seed suspicious domain data.
	seedSuspiciousDomains(t, db, "already-blocked.test", 5)

	// Pre-add an override — audit should skip this domain.
	if err := db.UpsertOverride("already-blocked.test", "block", "manual block"); err != nil {
		t.Fatalf("upsert override: %v", err)
	}

	task := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences:      1,
		MaxPerCycle:         10,
		ConfidenceThreshold: 0.01, // very low threshold
		EnrichTimeout:       1 * time.Second,
	})

	// Set lastAudit far back so domain is included.
	task.mu.Lock()
	task.lastAudit = time.Now().Add(-48 * time.Hour)
	task.mu.Unlock()

	err := task.Run(context.Background())
	if err != nil {
		t.Fatalf("audit run error: %v", err)
	}

	// Verify the override is unchanged (still manual, not agent).
	override, _ := db.GetOverride("already-blocked.test")
	if override == nil {
		t.Fatal("expected override to still exist")
	}
	if override.Reason != "manual block" {
		t.Errorf("expected original reason preserved, got %q", override.Reason)
	}
}

func TestAuditTaskLimitPerCycle(t *testing.T) {
	db := newTestStore(t)

	// Seed a few suspicious domains with enough occurrences.
	for i := 0; i < 5; i++ {
		domain := "suspicious-" + string(rune('a'+i)) + ".test"
		seedSuspiciousDomains(t, db, domain, 5)
	}

	task := NewAuditTask(db, nil, nil, AuditConfig{
		MinOccurrences: 1,
		MaxPerCycle:    2, // only process 2 per cycle
		EnrichTimeout:  1 * time.Second,
	})

	task.mu.Lock()
	task.lastAudit = time.Now().Add(-48 * time.Hour)
	task.mu.Unlock()

	err := task.Run(context.Background())
	if err != nil {
		t.Fatalf("audit run error: %v", err)
	}

	// The audit should have processed at most MaxPerCycle domains.
	// Verify via audit log events (each domain gets a "reviewed" or "auto_block" event,
	// plus one "audit_completed" summary event).
	events, _ := db.QueryAgentEvents(time.Now().Add(-1*time.Hour), nil, 100)
	if len(events) == 0 {
		t.Error("expected at least some audit events")
	}
	// Count non-summary events: should be at most MaxPerCycle.
	domainEvents := 0
	for _, e := range events {
		if e.EventType == "reviewed" || e.EventType == "auto_block" {
			domainEvents++
		}
	}
	if domainEvents > 2 {
		t.Errorf("expected at most 2 domain events (MaxPerCycle), got %d", domainEvents)
	}
}
