package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCollectCodeSettingsFindsQuotedNames(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "risk", "env.go"),
		`config.String("SAFE_ZONE_FEED_TTL_DAYS", 14)`+"\n"+
			`os.Getenv("SAFE_ZONE_WHITELIST_PATH")`+"\n")
	writeFile(t, filepath.Join(root, "cmd", "core-api", "main.go"),
		`config.Bool("SAFE_ZONE_AGENT_ENABLED", false)`+"\n")

	settings, err := collectCodeSettings(root)
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]bool{
		"SAFE_ZONE_FEED_TTL_DAYS":  false,
		"SAFE_ZONE_WHITELIST_PATH": false,
		"SAFE_ZONE_AGENT_ENABLED":  false,
	}
	for _, name := range settings {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("expected %s to be collected, got %v", name, settings)
		}
	}
}

func TestCollectCodeSettingsIgnoresTestFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "internal", "risk", "env_test.go"),
		`config.String("SAFE_ZONE_ONLY_IN_A_TEST", 1)`+"\n")

	settings, err := collectCodeSettings(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range settings {
		if name == "SAFE_ZONE_ONLY_IN_A_TEST" {
			t.Fatal("a test file must not contribute a documented setting")
		}
	}
}

func TestCollectExampleSettingsCountsCommentedEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.example")
	writeFile(t, path, "SAFE_ZONE_LIVE=1\n"+
		"# SAFE_ZONE_COMMENTED=2\n"+
		"# a comment that is not a setting\n"+
		"SAFE_ZONE_OTHER=3\n")

	settings, err := collectExampleSettings(path)
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, name := range settings {
		found[name] = true
	}
	for _, name := range []string{"SAFE_ZONE_LIVE", "SAFE_ZONE_COMMENTED", "SAFE_ZONE_OTHER"} {
		if !found[name] {
			t.Errorf("expected %s to be documented, got %v", name, settings)
		}
	}
}

func TestIgnoredPrefixes(t *testing.T) {
	if !isIgnored("SAFE_ZONE_URL_ML_FEEDBACK_SECRET") {
		t.Error("a family prefix must be ignored")
	}
	if isIgnored("SAFE_ZONE_URL_ML_MODE") {
		t.Error("an unrelated setting must not be ignored")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
