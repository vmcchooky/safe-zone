package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEvaluateCombinesModelFeedAndTrustedBrandBypass(t *testing.T) {
	dir := t.TempDir()
	labels := writeFixture(t, dir, "labels.csv", "case_id,domain,human_label,reviewer_id\nmal-model,model.evil,malicious,owner\nmal-feed,login.feed.test,malicious,owner\nbenign-brand,mail.google.com,benign,owner\n")
	predictions := writeFixture(t, dir, "predictions.jsonl", "{\"case_id\":\"mal-model\",\"domain\":\"model.evil\",\"human_label\":\"malicious\",\"probability\":0.99,\"would_block\":true}\n{\"case_id\":\"mal-feed\",\"domain\":\"login.feed.test\",\"human_label\":\"malicious\",\"probability\":0.20,\"would_block\":false}\n{\"case_id\":\"benign-brand\",\"domain\":\"mail.google.com\",\"human_label\":\"benign\",\"probability\":0.10,\"would_block\":false}\n")
	feedPath := writeFixture(t, dir, "feed.txt", "feed.test\ngoogle.com\n")
	cfg := protocol{
		SchemaVersion:   reportSchemaVersion,
		AsOf:            "2026-08-24T10:00:00Z",
		FeedTTLHours:    336,
		StaleAfterHours: 36,
		WhitelistState:  "fixture_not_whitelisted",
		Labels:          fileRef{Path: labels, SHA256: hashFile(t, labels)},
		Predictions:     predictionRef{fileRef: fileRef{Path: predictions, SHA256: hashFile(t, predictions)}, ModelSHA256: "model", Threshold: 0.92},
		ExpectedLabels:  map[string]int{"malicious": 2, "benign": 1},
		Sources:         []sourceConfig{{Name: "fixture", Path: feedPath, SHA256: hashFile(t, feedPath), CollectedAt: "2026-08-24T09:00:00Z"}},
	}
	cfgPath := filepath.Join(dir, "config.json")
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "report.json")
	if err := run(cfgPath, output); err != nil {
		t.Fatal(err)
	}
	var got report
	reportData, err := os.ReadFile(output)
	if err != nil || json.Unmarshal(reportData, &got) != nil {
		t.Fatalf("read report: %v", err)
	}
	malicious := got.Coverage["malicious"]
	benign := got.Coverage["benign"]
	if malicious.ModelWouldBlock != 1 || malicious.FeedOnly != 1 || malicious.CombinedWouldBlock != 2 || malicious.Neither != 0 {
		t.Fatalf("unexpected malicious coverage: %+v", malicious)
	}
	if benign.FeedMatch != 0 || benign.TrustedBrandBypass != 1 || got.RecoveryRate != 1 {
		t.Fatalf("unexpected benign/recovery result: benign=%+v recovery=%g", benign, got.RecoveryRate)
	}
}

func TestEvaluateExcludesExpiredSource(t *testing.T) {
	cases := []evaluationCase{{CaseID: "mal", Domain: "bad.test", HumanLabel: "malicious"}}
	predictions := map[string]prediction{"mal": {CaseID: "mal", Domain: "bad.test", HumanLabel: "malicious", Probability: 0.1}}
	sources := []loadedSource{{config: sourceConfig{Name: "expired"}, domains: map[string]struct{}{"bad.test": {}}, expired: true}}
	rep := evaluate(protocol{AsOf: "2026-08-24T10:00:00Z", Predictions: predictionRef{ModelSHA256: "model"}}, "protocol", "labels", "predictions", cases, predictions, sources)
	malicious := rep.Coverage["malicious"]
	if malicious.FeedMatch != 0 || malicious.Neither != 1 || rep.ResidualMalicious != 1 {
		t.Fatalf("expired source affected coverage: %+v", malicious)
	}
}

func TestLoadSourceRejectsChecksumDrift(t *testing.T) {
	path := writeFixture(t, t.TempDir(), "feed.txt", "bad.test\n")
	_, err := loadSource(sourceConfig{Name: "bad", Path: path, SHA256: "deadbeef", CollectedAt: "2026-08-24T09:00:00Z"}, mustTime(t, "2026-08-24T10:00:00Z"), 36*time.Hour, 336*time.Hour)
	if err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func mustTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func writeFixture(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
