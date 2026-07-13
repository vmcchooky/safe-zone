package store

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := New(path, 30)
	if err != nil {
		t.Fatalf("failed to create test db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close test db: %v", err)
		}
	})
	return db
}

func TestNewCreatesDatabase(t *testing.T) {
	db := newTestDB(t)
	if !db.Enabled() {
		t.Fatal("expected db to be enabled")
	}
}

func TestNewDisabledWhenPathEmpty(t *testing.T) {
	db, err := New("", 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if db != nil {
		t.Fatal("expected nil db for empty path")
	}
}

func TestInMemoryDatabaseSupportsSystemConfig(t *testing.T) {
	db, err := New(":memory:", 30)
	if err != nil {
		t.Fatalf("failed to create in-memory db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("failed to close in-memory db: %v", err)
		}
	})

	if err := db.SetSystemConfig(context.Background(), "analysis_config", `{"long_domain_length":40}`); err != nil {
		t.Fatalf("expected in-memory system config write to succeed: %v", err)
	}
	got, err := db.GetSystemConfig(context.Background(), "analysis_config")
	if err != nil {
		t.Fatalf("expected in-memory system config read to succeed: %v", err)
	}
	if got == "" {
		t.Fatal("expected persisted in-memory system config value")
	}
}

func TestOSINTEvidenceRoundTrip(t *testing.T) {
	db := newTestDB(t)
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
	err := db.ReplaceOSINTEvidence(context.Background(), "baohiem-online.com", []OSINTEvidence{{
		Domain:       "baohiem-online.com",
		SourceURL:    "https://example.gov.vn/canh-bao",
		SourceTitle:  "Cảnh báo",
		SourceType:   "official_warning",
		Confidence:   0.95,
		MatchedTerms: []string{"giả mạo", "lừa đảo"},
		RetrievedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		ExpiresAt:    expires,
	}})
	if err != nil {
		t.Fatal(err)
	}

	items, err := db.ListOSINTEvidence(context.Background(), "baohiem-online.com", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("expected one evidence item, got %d", len(items))
	}
	if items[0].SourceType != "official_warning" || len(items[0].MatchedTerms) != 2 {
		t.Fatalf("unexpected evidence item: %#v", items[0])
	}
}

func TestNilDBEnabled(t *testing.T) {
	var db *DB
	if db.Enabled() {
		t.Fatal("nil db should not be enabled")
	}
}

func TestNilDBClose(t *testing.T) {
	var db *DB
	if err := db.Close(); err != nil {
		t.Fatalf("nil close should not error: %v", err)
	}
}

func TestBrandCRUDAndDefaultSeed(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()

	brands, err := db.ListBrands(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(brands) == 0 {
		t.Fatal("expected default trusted brands to be seeded")
	}

	created, err := db.CreateBrand(ctx, analysis.Brand{
		Name:           "Quorix",
		OfficialDomain: "Quorix.io.vn",
		AltDomains:     []string{"safe.quorix.io.vn", "safe.quorix.io.vn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID == 0 {
		t.Fatal("expected created brand id")
	}
	if created.Name != "quorix" || created.OfficialDomain != "quorix.io.vn" {
		t.Fatalf("expected normalized brand, got %#v", created)
	}
	if len(created.AltDomains) != 1 || created.AltDomains[0] != "safe.quorix.io.vn" {
		t.Fatalf("expected normalized/deduplicated alt domains, got %#v", created.AltDomains)
	}

	updated, err := db.UpdateBrand(ctx, created.ID, analysis.Brand{
		Name:           "quorix",
		OfficialDomain: "quorix.com",
		AltDomains:     []string{"quorix.io.vn"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.OfficialDomain != "quorix.com" {
		t.Fatalf("expected updated official domain, got %s", updated.OfficialDomain)
	}

	if err := db.DeleteBrand(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetBrand(ctx, created.ID); err == nil {
		t.Fatal("expected deleted brand to be absent")
	}
}

func TestWhitelistCountAndStream(t *testing.T) {
	db := newTestDB(t)
	domains := []string{"google.com", "facebook.com", "googlevideo.com"}

	if err := db.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatal(err)
	}

	count, err := db.GetWhitelistCount(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if count != len(domains) {
		t.Fatalf("expected whitelist count %d, got %d", len(domains), count)
	}

	var streamed []string
	if err := db.StreamWhitelist(context.Background(), func(domain string) error {
		streamed = append(streamed, domain)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	sort.Strings(domains)
	sort.Strings(streamed)
	if !reflect.DeepEqual(streamed, domains) {
		t.Fatalf("expected streamed whitelist %v, got %v", domains, streamed)
	}
}

func TestStreamWhitelistPropagatesCallbackError(t *testing.T) {
	db := newTestDB(t)
	if err := db.UpdateWhitelist(context.Background(), []string{"google.com"}); err != nil {
		t.Fatal(err)
	}

	sentinel := errors.New("stop")
	err := db.StreamWhitelist(context.Background(), func(domain string) error {
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("expected callback error to propagate, got %v", err)
	}
}

// --- Override Tests ---

func TestUpsertAndGetOverride(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "evil.com", "block", "phishing site"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	override, err := db.GetOverride(context.Background(), "evil.com")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if override == nil {
		t.Fatal("expected override, got nil")
	}
	if override.Domain != "evil.com" {
		t.Fatalf("expected domain evil.com, got %s", override.Domain)
	}
	if override.Action != "block" {
		t.Fatalf("expected action block, got %s", override.Action)
	}
	if override.Reason != "phishing site" {
		t.Fatalf("expected reason 'phishing site', got %s", override.Reason)
	}
}

func TestUpsertUpdatesExisting(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "test.com", "block", "initial"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if err := db.UpsertOverride(context.Background(), "test.com", "allow", "updated reason"); err != nil {
		t.Fatalf("upsert update failed: %v", err)
	}

	override, err := db.GetOverride(context.Background(), "test.com")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if override.Action != "allow" {
		t.Fatalf("expected updated action allow, got %s", override.Action)
	}
	if override.Reason != "updated reason" {
		t.Fatalf("expected updated reason, got %s", override.Reason)
	}
}

func TestUpsertInvalidAction(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "test.com", "invalid", "reason"); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestGetOverrideParentDomain(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "example.com", "block", "block entire domain"); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}

	// Subdomain should match parent override.
	override, err := db.GetOverride(context.Background(), "mail.example.com")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if override == nil {
		t.Fatal("expected parent domain override to match subdomain")
	}
	if override.Domain != "example.com" {
		t.Fatalf("expected matched domain example.com, got %s", override.Domain)
	}

	// Deep subdomain should also match.
	override, err = db.GetOverride(context.Background(), "deep.sub.example.com")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if override == nil {
		t.Fatal("expected parent domain override to match deep subdomain")
	}
}

func TestGetOverrideNotFound(t *testing.T) {
	db := newTestDB(t)

	override, err := db.GetOverride(context.Background(), "nonexistent.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if override != nil {
		t.Fatal("expected nil for nonexistent domain")
	}
}

func TestDeleteOverride(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "delete-me.com", "block", ""); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if err := db.DeleteOverride(context.Background(), "delete-me.com"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}

	override, err := db.GetOverride(context.Background(), "delete-me.com")
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if override != nil {
		t.Fatal("expected nil after delete")
	}
}

func TestDeleteOverrideNotFound(t *testing.T) {
	db := newTestDB(t)

	if err := db.DeleteOverride(context.Background(), "nonexistent.com"); err == nil {
		t.Fatal("expected error for deleting nonexistent override")
	}
}

func TestListOverrides(t *testing.T) {
	db := newTestDB(t)

	if err := db.UpsertOverride(context.Background(), "allow.com", "allow", "trusted"); err != nil {
		t.Fatal(err)
	}
	if err := db.UpsertOverride(context.Background(), "block.com", "block", "dangerous"); err != nil {
		t.Fatal(err)
	}

	all, err := db.ListOverrides(context.Background(), "")
	if err != nil {
		t.Fatalf("list all failed: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 overrides, got %d", len(all))
	}

	allowed, err := db.ListOverrides(context.Background(), "allow")
	if err != nil {
		t.Fatalf("list allow failed: %v", err)
	}
	if len(allowed) != 1 || allowed[0].Domain != "allow.com" {
		t.Fatalf("expected 1 allow override, got %d", len(allowed))
	}

	blocked, err := db.ListOverrides(context.Background(), "block")
	if err != nil {
		t.Fatalf("list block failed: %v", err)
	}
	if len(blocked) != 1 || blocked[0].Domain != "block.com" {
		t.Fatalf("expected 1 block override, got %d", len(blocked))
	}
}

// --- Telemetry Tests ---

func TestRecordAndQueryRecent(t *testing.T) {
	db := newTestDB(t)

	db.RecordAnalysis(TelemetryEntry{
		Domain:     "example.com",
		Verdict:    "SAFE",
		Score:      0,
		Confidence: 1.0,
		Reasons:    []string{"whitelisted"},
		CacheHit:   false,
		Source:     "whitelist",
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})
	db.RecordAnalysis(TelemetryEntry{
		Domain:     "phish.test",
		Verdict:    "MALICIOUS",
		Score:      100,
		Confidence: 1.0,
		Reasons:    []string{"matched local threat feed"},
		CacheHit:   false,
		Source:     "feed",
		AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
	})

	// Give the async writer time to flush.
	time.Sleep(100 * time.Millisecond)

	entries, err := db.QueryRecent(context.Background(), 10, 0)
	if err != nil {
		t.Fatalf("query recent failed: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	// Most recent first.
	if entries[0].Domain != "phish.test" {
		t.Fatalf("expected most recent domain phish.test, got %s", entries[0].Domain)
	}
	if entries[1].Domain != "example.com" {
		t.Fatalf("expected second domain example.com, got %s", entries[1].Domain)
	}
}

func TestQueryRecentPagination(t *testing.T) {
	db := newTestDB(t)

	for i := 0; i < 5; i++ {
		db.RecordAnalysis(TelemetryEntry{
			Domain:     "domain" + string(rune('A'+i)) + ".com",
			Verdict:    "SAFE",
			Score:      0,
			Confidence: 1.0,
			Source:     "lexical",
			AnalyzedAt: time.Now().UTC().Format(time.RFC3339Nano),
		})
	}
	time.Sleep(100 * time.Millisecond)

	page1, err := db.QueryRecent(context.Background(), 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected 2 entries on page 1, got %d", len(page1))
	}

	page2, err := db.QueryRecent(context.Background(), 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 {
		t.Fatalf("expected 2 entries on page 2, got %d", len(page2))
	}

	if page1[0].Domain == page2[0].Domain {
		t.Fatal("page 1 and page 2 should have different entries")
	}
}

func TestQueryStats(t *testing.T) {
	db := newTestDB(t)

	now := time.Now().UTC()
	db.RecordAnalysis(TelemetryEntry{Domain: "a.com", Verdict: "SAFE", Score: 0, Confidence: 1.0, CacheHit: true, Source: "cache", AnalyzedAt: now.Format(time.RFC3339Nano)})
	db.RecordAnalysis(TelemetryEntry{Domain: "b.com", Verdict: "SUSPICIOUS", Score: 50, Confidence: 0.6, Source: "lexical", AnalyzedAt: now.Format(time.RFC3339Nano)})
	db.RecordAnalysis(TelemetryEntry{Domain: "c.com", Verdict: "MALICIOUS", Score: 100, Confidence: 1.0, CacheHit: true, Source: "feed", AnalyzedAt: now.Format(time.RFC3339Nano)})

	time.Sleep(100 * time.Millisecond)

	stats, err := db.QueryStats(context.Background(), "24h")
	if err != nil {
		t.Fatalf("query stats failed: %v", err)
	}
	if stats.Total != 3 {
		t.Fatalf("expected total 3, got %d", stats.Total)
	}
	if stats.Safe != 1 {
		t.Fatalf("expected safe 1, got %d", stats.Safe)
	}
	if stats.Suspicious != 1 {
		t.Fatalf("expected suspicious 1, got %d", stats.Suspicious)
	}
	if stats.Malicious != 1 {
		t.Fatalf("expected malicious 1, got %d", stats.Malicious)
	}
	if stats.CacheHits != 2 {
		t.Fatalf("expected cache_hits 2, got %d", stats.CacheHits)
	}
	wantScoreBands := []ScoreBand{
		{Label: "0-20", Value: 1},
		{Label: "21-40", Value: 0},
		{Label: "41-60", Value: 1},
		{Label: "61-80", Value: 0},
		{Label: "81-100", Value: 1},
	}
	if !reflect.DeepEqual(stats.ScoreBands, wantScoreBands) {
		t.Fatalf("unexpected score bands: got %#v, want %#v", stats.ScoreBands, wantScoreBands)
	}
	var trendTotal int64
	for _, point := range stats.Trend {
		trendTotal += point.Safe + point.Suspicious + point.Malicious
	}
	if trendTotal != stats.Total {
		t.Fatalf("trend total %d does not match aggregate total %d", trendTotal, stats.Total)
	}
}

func TestTelemetryCleanup(t *testing.T) {
	db := newTestDB(t)
	db.retentionDays = 0 // Expire everything immediately.

	past := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	db.RecordAnalysis(TelemetryEntry{Domain: "old.com", Verdict: "SAFE", Score: 0, Confidence: 1.0, Source: "lexical", AnalyzedAt: past})

	time.Sleep(100 * time.Millisecond)

	db.cleanup()

	entries, err := db.QueryRecent(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries after cleanup, got %d", len(entries))
	}
}

func TestRecordAnalysisNilDB(t *testing.T) {
	var db *DB
	// Should not panic.
	db.RecordAnalysis(TelemetryEntry{Domain: "test.com"})
}

func TestRecordAnalysisBufferFull(t *testing.T) {
	db := newTestDB(t)

	// Fill the buffer completely — close done channel first to stop writer.
	close(db.done)
	db.wg.Wait()

	// Reset for our test: create a tiny buffer.
	db.done = make(chan struct{})
	db.telemetryCh = make(chan TelemetryEntry, 1)

	// Fill buffer.
	db.telemetryCh <- TelemetryEntry{Domain: "fill.com"}

	// This should not block even though the buffer is full.
	done := make(chan struct{})
	go func() {
		db.RecordAnalysis(TelemetryEntry{Domain: "overflow.com"})
		close(done)
	}()

	select {
	case <-done:
		// Good, did not block.
	case <-time.After(time.Second):
		t.Fatal("RecordAnalysis blocked when buffer was full")
	}
}

// --- Disabled store tests ---

func TestDisabledGetOverride(t *testing.T) {
	var db *DB
	override, err := db.GetOverride(context.Background(), "test.com")
	if err != nil {
		t.Fatal(err)
	}
	if override != nil {
		t.Fatal("expected nil from disabled store")
	}
}

func TestDisabledListOverrides(t *testing.T) {
	var db *DB
	overrides, err := db.ListOverrides(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if overrides != nil {
		t.Fatal("expected nil from disabled store")
	}
}

func TestDisabledQueryRecent(t *testing.T) {
	var db *DB
	entries, err := db.QueryRecent(context.Background(), 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if entries != nil {
		t.Fatal("expected nil from disabled store")
	}
}

func TestDisabledQueryStats(t *testing.T) {
	var db *DB
	stats, err := db.QueryStats(context.Background(), "24h")
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 0 {
		t.Fatal("expected zero stats from disabled store")
	}
}

// --- Whitelist Tests ---

func TestWhitelistStore(t *testing.T) {
	db := newTestDB(t)

	domains := []string{"google.com", "facebook.com", "github.com", "google.com"} // includes duplicate

	if err := db.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}

	// Verify duplicates are ignored and we only have unique entries
	list, err := db.GetWhitelist(context.Background())
	if err != nil {
		t.Fatalf("failed to get whitelist: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 unique domains, got %d: %v", len(list), list)
	}

	// Verify lookup
	for _, d := range []string{"google.com", "facebook.com", "github.com"} {
		ok, err := db.IsDomainWhitelisted(context.Background(), d)
		if err != nil {
			t.Fatalf("IsDomainWhitelisted error for %s: %v", d, err)
		}
		if !ok {
			t.Fatalf("expected domain %s to be whitelisted", d)
		}
	}

	// Negative lookup
	ok, err := db.IsDomainWhitelisted(context.Background(), "evil.com")
	if err != nil {
		t.Fatalf("IsDomainWhitelisted error: %v", err)
	}
	if ok {
		t.Fatal("expected evil.com to not be whitelisted")
	}

	// Overwrite whitelist
	newDomains := []string{"apple.com", "microsoft.com"}
	if err := db.UpdateWhitelist(context.Background(), newDomains); err != nil {
		t.Fatalf("failed to update whitelist: %v", err)
	}

	// Old domains should be gone
	ok, err = db.IsDomainWhitelisted(context.Background(), "google.com")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected old domain google.com to be removed from whitelist")
	}

	// New domains should be present
	ok, err = db.IsDomainWhitelisted(context.Background(), "apple.com")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected new domain apple.com to be whitelisted")
	}
}

func TestDisabledWhitelist(t *testing.T) {
	var db *DB

	// Nil store should not error and return safe/empty defaults
	if err := db.UpdateWhitelist(context.Background(), []string{"google.com"}); err != nil {
		t.Fatalf("nil store UpdateWhitelist should not error: %v", err)
	}

	ok, err := db.IsDomainWhitelisted(context.Background(), "google.com")
	if err != nil {
		t.Fatalf("nil store IsDomainWhitelisted should not error: %v", err)
	}
	if ok {
		t.Fatal("nil store should return false for IsDomainWhitelisted")
	}

	list, err := db.GetWhitelist(context.Background())
	if err != nil {
		t.Fatalf("nil store GetWhitelist should not error: %v", err)
	}
	if list != nil {
		t.Fatal("nil store should return nil slice for GetWhitelist")
	}
}

func TestUpdateWhitelistBulkInsertChunks(t *testing.T) {
	db := newTestDB(t)

	domains := make([]string, 0, whitelistInsertChunkSize*2+25)
	for i := 0; i < whitelistInsertChunkSize*2+25; i++ {
		domains = append(domains, fmt.Sprintf("domain-%04d.example", i))
	}
	domains = append(domains, "")
	domains = append(domains, "domain-0001.example")
	domains = append(domains, "domain-0500.example")

	if err := db.UpdateWhitelist(context.Background(), domains); err != nil {
		t.Fatalf("failed to bulk update whitelist: %v", err)
	}

	list, err := db.GetWhitelist(context.Background())
	if err != nil {
		t.Fatalf("failed to read whitelist after bulk update: %v", err)
	}

	expected := whitelistInsertChunkSize*2 + 25
	if len(list) != expected {
		t.Fatalf("expected %d unique domains after chunked insert, got %d", expected, len(list))
	}

	for _, domain := range []string{"domain-0001.example", "domain-0500.example", "domain-1024.example"} {
		ok, err := db.IsDomainWhitelisted(context.Background(), domain)
		if err != nil {
			t.Fatalf("IsDomainWhitelisted(%s) error: %v", domain, err)
		}
		if !ok {
			t.Fatalf("expected %s to be whitelisted after chunked insert", domain)
		}
	}
}

// --- Multi-Tenant Unit Tests ---

func TestClientGroupsCRUD(t *testing.T) {
	db := newTestDB(t)

	// Test ListGroups initially has the 'default' group
	groups, err := db.ListGroups(context.Background())
	if err != nil {
		t.Fatalf("failed to list groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 initial group (default), got %d", len(groups))
	}
	if groups[0].Name != "default" {
		t.Fatalf("expected group name 'default', got %s", groups[0].Name)
	}

	// 1. Create a new group
	kidsID, err := db.CreateGroup(context.Background(), "kids", "Kids Policy", []string{"social_media", "adult"}, false, true)
	if err != nil {
		t.Fatalf("failed to create kids group: %v", err)
	}
	if kidsID <= 0 {
		t.Fatalf("expected positive auto-increment id, got %d", kidsID)
	}

	// Get Group and verify
	g, err := db.GetGroup(context.Background(), kidsID)
	if err != nil {
		t.Fatalf("failed to get group: %v", err)
	}
	if g.Name != "kids" || g.Description != "Kids Policy" || g.StrictPhishing || !g.StrictMalware {
		t.Fatalf("group values mismatch: %+v", g)
	}
	if len(g.BlockCategories) != 2 || g.BlockCategories[0] != "social_media" || g.BlockCategories[1] != "adult" {
		t.Fatalf("block categories mismatch: %v", g.BlockCategories)
	}

	// 2. Update Group
	err = db.UpdateGroup(context.Background(), kidsID, "kids-updated", "Updated Description", []string{"gaming"}, true, false)
	if err != nil {
		t.Fatalf("failed to update group: %v", err)
	}

	g, err = db.GetGroup(context.Background(), kidsID)
	if err != nil {
		t.Fatalf("failed to get group after update: %v", err)
	}
	if g.Name != "kids-updated" || g.Description != "Updated Description" || !g.StrictPhishing || g.StrictMalware {
		t.Fatalf("updated group values mismatch: %+v", g)
	}
	if len(g.BlockCategories) != 1 || g.BlockCategories[0] != "gaming" {
		t.Fatalf("updated block categories mismatch: %v", g.BlockCategories)
	}

	// Get by name
	gByName, err := db.GetGroupByName(context.Background(), "kids-updated")
	if err != nil {
		t.Fatalf("failed to get group by name: %v", err)
	}
	if gByName.ID != kidsID {
		t.Fatalf("expected group ID %d, got %d", kidsID, gByName.ID)
	}

	// 3. Attempt to delete default group (should fail)
	err = db.DeleteGroup(context.Background(), 1)
	if err == nil {
		t.Fatal("expected error when deleting default group, got nil")
	}

	// 4. Delete group
	err = db.DeleteGroup(context.Background(), kidsID)
	if err != nil {
		t.Fatalf("failed to delete group: %v", err)
	}

	_, err = db.GetGroup(context.Background(), kidsID)
	if err == nil {
		t.Fatal("expected error getting deleted group, got nil")
	}
}

func TestClientMappings(t *testing.T) {
	db := newTestDB(t)

	// Create group
	grpID, err := db.CreateGroup(context.Background(), "test-group", "Desc", []string{}, false, false)
	if err != nil {
		t.Fatalf("failed to create group: %v", err)
	}

	// 1. Add mappings
	ipMapID, err := db.AddMappingInt(context.Background(), "ip", "192.168.1.10", grpID)
	if err != nil {
		t.Fatalf("failed to add IP mapping: %v", err)
	}

	cidrMapID, err := db.AddMappingInt(context.Background(), "cidr", "10.0.0.0/24", grpID)
	if err != nil {
		t.Fatalf("failed to add CIDR mapping: %v", err)
	}

	clientIdMapID, err := db.AddMappingInt(context.Background(), "client_id", "iphone-user", grpID)
	if err != nil {
		t.Fatalf("failed to add Client ID mapping: %v", err)
	}

	// 2. Validate IP / CIDR validation
	_, err = db.AddMappingInt(context.Background(), "ip", "invalid-ip", grpID)
	if err == nil {
		t.Fatal("expected error for invalid IP mapping, got nil")
	}

	_, err = db.AddMappingInt(context.Background(), "cidr", "10.0.0.300/24", grpID)
	if err == nil {
		t.Fatal("expected error for invalid CIDR mapping, got nil")
	}

	_, err = db.AddMappingInt(context.Background(), "invalid_type", "value", grpID)
	if err == nil {
		t.Fatal("expected error for invalid mapping type, got nil")
	}

	// 3. List and check
	mappings, err := db.ListMappings(context.Background())
	if err != nil {
		t.Fatalf("failed to list mappings: %v", err)
	}
	if len(mappings) != 3 {
		t.Fatalf("expected 3 mappings, got %d", len(mappings))
	}

	// Test mapping values
	var foundIP, foundCIDR, foundClientID bool
	for _, m := range mappings {
		if m.ID == ipMapID && m.MappingType == "ip" && m.Value == "192.168.1.10" && m.GroupID == grpID && m.GroupName == "test-group" {
			foundIP = true
		}
		if m.ID == cidrMapID && m.MappingType == "cidr" && m.Value == "10.0.0.0/24" && m.GroupID == grpID && m.GroupName == "test-group" {
			foundCIDR = true
		}
		if m.ID == clientIdMapID && m.MappingType == "client_id" && m.Value == "iphone-user" && m.GroupID == grpID && m.GroupName == "test-group" {
			foundClientID = true
		}
	}
	if !foundIP || !foundCIDR || !foundClientID {
		t.Fatalf("some mappings were not found or malformed: %+v", mappings)
	}

	// 4. Delete mappings
	err = db.DeleteMapping(context.Background(), ipMapID)
	if err != nil {
		t.Fatalf("failed to delete mapping: %v", err)
	}

	mappings, err = db.ListMappings(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 {
		t.Fatalf("expected 2 mappings after deletion, got %d", len(mappings))
	}
}

func TestGetGroupForClient(t *testing.T) {
	db := newTestDB(t)

	// Create test groups
	kidsID, err := db.CreateGroup(context.Background(), "kids", "Kids group", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}
	iotID, err := db.CreateGroup(context.Background(), "iot", "IoT group", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	// Add Mappings
	// 1. CIDR block mapping for kids group
	_, err = db.AddMappingInt(context.Background(), "cidr", "192.168.1.0/24", kidsID)
	if err != nil {
		t.Fatal(err)
	}
	// 2. Specific IP mapping for iot group (within the CIDR range to test priority)
	_, err = db.AddMappingInt(context.Background(), "ip", "192.168.1.50", iotID)
	if err != nil {
		t.Fatal(err)
	}
	// 3. Client ID mapping for kids group
	_, err = db.AddMappingInt(context.Background(), "client_id", "my-tablet", kidsID)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name     string
		ip       string
		clientID string
		expected string // group name
	}{
		{"Client ID Match", "8.8.8.8", "my-tablet", "kids"},
		{"IP Priority Match", "192.168.1.50", "", "iot"},
		{"CIDR Subnet Match", "192.168.1.20", "", "kids"},
		{"Fallback Default", "8.8.8.8", "", "default"},
		{"Client ID Priority over IP", "192.168.1.50", "my-tablet", "kids"}, // Client ID matches kids, IP matches iot. Client ID checked first.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			grp, err := db.GetGroupForClient(context.Background(), tt.ip, tt.clientID)
			if err != nil {
				t.Fatalf("failed to resolve group: %v", err)
			}
			if grp.Name != tt.expected {
				t.Fatalf("expected group %q, got %q", tt.expected, grp.Name)
			}
		})
	}
}

func TestGetEffectiveOverride(t *testing.T) {
	db := newTestDB(t)

	// Create test group
	grpID, err := db.CreateGroup(context.Background(), "vip", "VIP group", []string{}, false, false)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Setup Group Override
	err = db.UpsertGroupOverride(context.Background(), grpID, "youtube.com", "block", "kids block youtube")
	if err != nil {
		t.Fatalf("failed to upsert group override: %v", err)
	}

	// 2. Setup Global Overrides
	err = db.UpsertOverride(context.Background(), "youtube.com", "allow", "global allow youtube")
	if err != nil {
		t.Fatal(err)
	}
	err = db.UpsertOverride(context.Background(), "facebook.com", "block", "global block facebook")
	if err != nil {
		t.Fatal(err)
	}

	// 3. Setup parent subdomain override
	err = db.UpsertGroupOverride(context.Background(), grpID, "co.uk", "block", "block UK domains")
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name           string
		groupID        int64
		domain         string
		expectedAction string
		expectedDomain string // matched override domain
	}{
		{"Group override preferred over global", grpID, "youtube.com", "block", "youtube.com"},
		{"Global override fallback", grpID, "facebook.com", "block", "facebook.com"},
		{"Subdomain inheritance on Group Override", grpID, "music.youtube.com", "block", "youtube.com"},
		{"Subdomain inheritance on General TLD Group Override", grpID, "bbc.co.uk", "block", "co.uk"},
		{"No override", grpID, "google.com", "", ""},
		{"Global fallback on subdomain", grpID, "sub.facebook.com", "block", "facebook.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			override, err := db.GetEffectiveOverride(context.Background(), tt.groupID, tt.domain)
			if err != nil {
				t.Fatalf("failed to get effective override: %v", err)
			}
			if tt.expectedAction == "" {
				if override != nil {
					t.Fatalf("expected nil override, got: %+v", override)
				}
			} else {
				if override == nil {
					t.Fatalf("expected override, got nil")
				}
				if override.Action != tt.expectedAction {
					t.Fatalf("expected action %q, got %q", tt.expectedAction, override.Action)
				}
				if override.Domain != tt.expectedDomain {
					t.Fatalf("expected matched domain %q, got %q", tt.expectedDomain, override.Domain)
				}
			}
		})
	}

	// 4. Test ListGroupOverrides
	ovs, err := db.ListGroupOverrides(context.Background(), grpID)
	if err != nil {
		t.Fatalf("failed to list group overrides: %v", err)
	}
	if len(ovs) != 2 {
		t.Fatalf("expected 2 group overrides, got %d", len(ovs))
	}

	// 5. Test DeleteGroupOverride
	err = db.DeleteGroupOverride(context.Background(), grpID, "youtube.com")
	if err != nil {
		t.Fatalf("failed to delete group override: %v", err)
	}

	ovs, err = db.ListGroupOverrides(context.Background(), grpID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ovs) != 1 {
		t.Fatalf("expected 1 group override after deletion, got %d", len(ovs))
	}
}

func TestWhoisCacheRoundTripAndExpiry(t *testing.T) {
	db := newTestDB(t)
	entry := WhoisCacheEntry{
		Domain:         "example.com",
		Found:          true,
		RegisteredDate: time.Now().Add(-30 * 24 * time.Hour).UTC(),
		DomainAgeDays:  30,
		Registrar:      "Example Registrar",
		PrivacyGuard:   true,
		Score:          5,
		Reasons:        []string{"whois: privacy guard enabled"},
		RawText:        "raw whois",
	}
	if err := db.SetWhoisCache(context.Background(), entry.Domain, entry, time.Hour); err != nil {
		t.Fatal(err)
	}

	got, ok, err := db.GetWhoisCache(context.Background(), entry.Domain, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.Registrar != entry.Registrar || got.RawText != entry.RawText || len(got.Reasons) != 1 {
		t.Fatalf("unexpected cached entry: %#v", got)
	}

	if _, ok, err := db.GetWhoisCache(context.Background(), entry.Domain, time.Now().Add(2*time.Hour)); err != nil || ok {
		t.Fatalf("expected expired cache miss, ok=%v err=%v", ok, err)
	}
}

func TestAnalysisConfigStoreRoundTrip(t *testing.T) {
	db := newTestDB(t)
	cfg := config.DefaultAnalysisConfig()
	cfg.LongDomainLength = 40
	if err := db.SetAnalysisConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got, err := db.GetAnalysisConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.LongDomainLength != 40 {
		t.Fatalf("unexpected config: %#v", got)
	}
}
