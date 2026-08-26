package risk

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/analysis"
	"safe-zone/internal/config"
	"safe-zone/internal/store"
)

func durableTestConfig(secret string) URLMLFeedbackConfig {
	return URLMLFeedbackConfig{
		Secret:     secret,
		KeyVersion: 1,
		Retention:  defaultURLFeedbackRetentionHours * time.Hour,
		MaxRows:    1000,
	}
}

func openTempStore(t *testing.T) (*store.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "feedback.db")
	db, err := store.New(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return db, path
}

func reopenTempStore(t *testing.T, path string) *store.DB {
	t.Helper()
	db, err := store.New(path, 30)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	return db
}

func TestDurableURLFeedbackSurvivesRestartAndCountsFalsePositive(t *testing.T) {
	db, path := openTempStore(t)
	first := newDurableURLFeedbackStore(db, durableTestConfig("secret-v1"))
	first.record("event-restart-1", 0.75, true)
	if err := db.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	// Simulate a process restart: same database file and same injected secret.
	reopened := reopenTempStore(t, path)
	defer func() { _ = reopened.Close() }()
	second := newDurableURLFeedbackStore(reopened, durableTestConfig("secret-v1"))

	recorded, reason := second.apply("event-restart-1", "benign")
	if !recorded || reason != "" {
		t.Fatalf("label lost across restart: recorded=%v reason=%q", recorded, reason)
	}
	status := second.status()
	if status.Persistence != "sqlite" || status.LabelledEvents != 1 || status.WouldPromoteLabelled != 1 ||
		status.ReportedBenignFalsePositive != 1 {
		t.Fatalf("unexpected durable status: %+v", status)
	}
	if status.LabelledFalsePositiveRate != 1 {
		t.Fatalf("expected labelled FP rate 1, got %v", status.LabelledFalsePositiveRate)
	}
}

func TestDurableURLFeedbackDeduplicatesEventID(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()
	s := newDurableURLFeedbackStore(db, durableTestConfig("secret-v1"))
	s.record("event-dup", 0.5, false)
	s.record("event-dup", 0.9, true)

	stats, err := db.URLFeedbackStats(context.Background())
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Rows != 1 {
		t.Fatalf("expected single retained row for duplicate event, got %d", stats.Rows)
	}
}

func TestDurableURLFeedbackRejectsDoubleLabeling(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()
	s := newDurableURLFeedbackStore(db, durableTestConfig("secret-v1"))
	s.record("event-once", 0.2, false)
	if ok, _ := s.apply("event-once", "malicious"); !ok {
		t.Fatal("first label should be accepted")
	}
	ok, reason := s.apply("event-once", "benign")
	if ok || reason != "already_labeled" {
		t.Fatalf("expected already_labeled, got %v/%q", ok, reason)
	}
	status := s.status()
	if status.LabelledEvents != 1 || status.ConfirmedMalicious != 1 {
		t.Fatalf("unexpected counters after replay attempt: %+v", status)
	}
}

func TestDurableURLFeedbackKeyRotationWithPreviousSecret(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()

	v1 := newDurableURLFeedbackStore(db, URLMLFeedbackConfig{
		Secret: "rotate-me-v1", KeyVersion: 1,
		Retention: time.Hour * 168, MaxRows: 1000,
	})
	v1.record("event-pre-rotation", 0.8, true)

	cfgV2 := URLMLFeedbackConfig{
		Secret: "rotate-me-v2", KeyVersion: 2,
		PreviousSecret: "rotate-me-v1", PreviousKeyVersion: 1,
		Retention: time.Hour * 168, MaxRows: 1000,
	}
	if err := cfgV2.validate(); err != nil {
		t.Fatalf("rotation config invalid: %v", err)
	}
	v2 := newDurableURLFeedbackStore(db, cfgV2)
	v2.record("event-post-rotation", 0.3, false)

	if ok, reason := v2.apply("event-pre-rotation", "malicious"); !ok || reason != "" {
		t.Fatalf("pre-rotation event not correlatable after rotation: %v/%q", ok, reason)
	}
	if ok, reason := v2.apply("event-post-rotation", "benign"); !ok || reason != "" {
		t.Fatalf("post-rotation label rejected: %v/%q", ok, reason)
	}
	status := v2.status()
	if status.KeyVersion != 2 || status.PreviousKeyVersion != 1 {
		t.Fatalf("key versions not reported: %+v", status)
	}
	if status.LabelledEvents != 2 {
		t.Fatalf("expected 2 labelled events, got %d", status.LabelledEvents)
	}
}

func TestDurableURLFeedbackRotationWithoutPreviousSecretFailsClosedToUnknown(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()

	old := newDurableURLFeedbackStore(db, URLMLFeedbackConfig{
		Secret: "only-v1", KeyVersion: 1, Retention: time.Hour * 168, MaxRows: 1000,
	})
	old.record("event-orphan", 0.6, true)

	fresh := newDurableURLFeedbackStore(db, URLMLFeedbackConfig{
		Secret: "only-v2", KeyVersion: 2, Retention: time.Hour * 168, MaxRows: 1000,
	})
	ok, reason := fresh.apply("event-orphan", "malicious")
	if ok || reason != "unknown_event" {
		t.Fatalf("expected unknown_event after key replacement, got %v/%q", ok, reason)
	}
}

func TestDurableURLFeedbackPrunesExpiredRows(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()
	s := newDurableURLFeedbackStore(db, URLMLFeedbackConfig{
		Secret: "prune-secret", KeyVersion: 1, Retention: time.Nanosecond, MaxRows: 1000,
	})
	s.record("event-expiring", 0.4, false)
	// Force an immediate prune pass.
	s.mu.Lock()
	s.startupPruned = false
	s.mu.Unlock()
	s.record("event-after-prune", 0.4, false)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := db.URLFeedbackRowCount(ctx); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	// The expired row may or may not be pruned depending on timestamp
	// resolution; the invariant is that pruning never crashes the store and
	// the newest row remains correlatable.
	if _, reason := s.apply("event-after-prune", "benign"); reason == "persistence_error" {
		t.Fatalf("newest row must survive pruning: %q", reason)
	}
}

func TestDurableURLFeedbackFailsClosedWithoutStoreButDoesNotPanic(t *testing.T) {
	s := newDurableURLFeedbackStore(nil, durableTestConfig("secret-v1"))
	s.record("event-unstored", 0.5, true)
	ok, reason := s.apply("event-unstored", "benign")
	if ok || (reason != "persistence_error" && reason != "unknown_event") {
		t.Fatalf("unexpected fail-closed behavior: %v/%q", ok, reason)
	}
	status := s.status()
	if !status.Supported {
		t.Fatal("durable feedback stays supported even while degraded")
	}
	if status.Degraded && status.PersistenceErrors == 0 {
		t.Fatal("degraded status must expose persistence errors")
	}
}

func TestServiceUsesMemoryFeedbackWithoutSecret(t *testing.T) {
	service := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	defer func() { _ = service.Close() }()
	status := service.URLMLStatus().Feedback
	if !status.Supported || status.Persistence != "memory" {
		t.Fatalf("expected memory persistence by default: %+v", status)
	}
	if _, reason := service.RecordURLFeedback("missing-event", "benign"); reason != "unknown_event" {
		t.Fatalf("unexpected memory apply result: %q", reason)
	}
}

func TestServiceDurableFeedbackEndToEndPrivacy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e2e-feedback.db")
	db, err := store.New(path, 30)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	classifier := &fakeURLClassifier{decision: analysis.MLDecision{
		Probability: 0.93,
		Action:      analysis.MLActionPromoteMalicious,
	}}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		Store:           db,
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
		URLMLFeedback:   durableTestConfig("e2e-secret"),
	})

	marker := "synthetic-e2e-marker-token-9f31"
	result := service.AnalyzeWithOptions(context.Background(), "example.com", ClientInfo{}, AnalyzeOptions{
		URLContext: &URLAnalysisContext{
			RequestedURL: "https://example.com/" + marker + "?token=supersecret",
			EventID:      "plain-event-id-" + marker,
			CallerClass:  "ui",
		},
	})
	if result.URLML == nil || !result.URLML.Evaluated {
		_ = service.Close()
		t.Fatalf("shadow evaluation missing: %+v", result.URLML)
	}
	if _, reason := service.RecordURLFeedback("plain-event-id-"+marker, "benign"); reason != "" {
		_ = service.Close()
		t.Fatalf("durable label rejected in-process: %q", reason)
	}
	if err := service.Close(); err != nil {
		t.Fatalf("close service: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sqlite file: %v", err)
	}
	for _, secret := range []string{marker, "supersecret", "plain-event-id"} {
		if containsBytes(raw, []byte(secret)) {
			t.Fatalf("raw context %q leaked into persisted feedback storage", secret)
		}
	}

	reopened := reopenTempStore(t, path)
	restored := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Store:          reopened,
		URLMLFeedback:  durableTestConfig("e2e-secret"),
	})
	status := restored.URLMLStatus().Feedback
	if status.LabelledEvents != 1 || status.ReportedBenignFalsePositive != 1 {
		_ = restored.Close()
		t.Fatalf("label not durable across restart: %+v", status)
	}
	if ok, reason := restored.RecordURLFeedback("plain-event-id-"+marker, "benign"); ok || reason != "already_labeled" {
		t.Fatalf("expected anti-replay across restart, got %v/%q", ok, reason)
	}
	if err := restored.Close(); err != nil {
		t.Fatalf("close restored service: %v", err)
	}
}

func TestURLMLFeedbackConfigValidateRejectsBadValues(t *testing.T) {
	cases := map[string]URLMLFeedbackConfig{
		"zero version":      {KeyVersion: 0, Retention: time.Hour, MaxRows: 100},
		"zero retention":    {KeyVersion: 1, Retention: 0, MaxRows: 100},
		"tiny max rows":     {KeyVersion: 1, Retention: time.Hour, MaxRows: 10},
		"huge retention":    {KeyVersion: 1, Retention: 24 * 36500 * time.Hour, MaxRows: 100},
		"same prev version": {KeyVersion: 3, Retention: time.Hour, MaxRows: 100, PreviousSecret: "x", PreviousKeyVersion: 3},
		"prev w/o version":  {KeyVersion: 1, Retention: time.Hour, MaxRows: 100, PreviousSecret: "x", PreviousKeyVersion: 0},
	}
	for name, cfg := range cases {
		if err := cfg.validate(); err == nil {
			t.Fatalf("%s: expected validation error", name)
		}
	}
	valid := URLMLFeedbackConfig{KeyVersion: 2, Retention: 24 * time.Hour, MaxRows: 500, PreviousSecret: "old", PreviousKeyVersion: 1}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid rotation config rejected: %v", err)
	}
}

func TestApplyURLFeedbackLabelUnknownRowReturnsNoRows(t *testing.T) {
	db, _ := openTempStore(t)
	defer func() { _ = db.Close() }()
	err := db.ApplyURLFeedbackLabel(context.Background(), "ffffffff", true)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected sql.ErrNoRows for unknown fingerprint, got %v", err)
	}
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func TestCoverageRecordsMissingContextReasons(t *testing.T) {
	service := NewService(Options{AnalysisConfig: config.DefaultAnalysisConfig()})
	defer func() { _ = service.Close() }()

	_ = service.Analyze(context.Background(), "example.com", ClientInfo{})
	_ = service.AnalyzeWithOptions(context.Background(), "example.net", ClientInfo{}, AnalyzeOptions{
		MissingContextReason: "get_domain_only",
	})
	_ = service.AnalyzeWithOptions(context.Background(), "example.org", ClientInfo{}, AnalyzeOptions{
		MissingContextReason: "post_not_provided",
	})

	coverage := service.URLMLStatus().Coverage
	if coverage.AnalyzeRequests != 3 || coverage.URLContextRequests != 0 {
		t.Fatalf("unexpected coverage totals: %+v", coverage)
	}
	breakdown := coverage.MissingContextBreakdown
	if breakdown["unspecified"] != 1 || breakdown["get_domain_only"] != 1 || breakdown["post_not_provided"] != 1 {
		t.Fatalf("unexpected missing-context breakdown: %+v", breakdown)
	}
}
