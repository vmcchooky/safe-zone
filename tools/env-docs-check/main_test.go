package main

import (
	"os"
	"path/filepath"
	"testing"
)

// openRoot opens a root scoped to dir, for the same reason the tool does.
func openRoot(t *testing.T, dir string) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return root
}

func TestCollectCodeSettingsFindsQuotedNames(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "internal", "risk", "env.go"),
		`config.String("SAFE_ZONE_FEED_TTL_DAYS", 14)`+"\n"+
			`os.Getenv("SAFE_ZONE_WHITELIST_PATH")`+"\n")
	writeFile(t, filepath.Join(dir, "cmd", "core-api", "main.go"),
		`config.Bool("SAFE_ZONE_AGENT_ENABLED", false)`+"\n")

	settings, err := collectCodeSettings(openRoot(t, dir))
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
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "internal", "risk", "env_test.go"),
		`config.String("SAFE_ZONE_ONLY_IN_A_TEST", 1)`+"\n")

	settings, err := collectCodeSettings(openRoot(t, dir))
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
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".env.example"),
		"SAFE_ZONE_LIVE=1\n"+
			"# SAFE_ZONE_COMMENTED=2\n"+
			"# a comment that is not a setting\n"+
			"SAFE_ZONE_OTHER=3\n")

	settings, err := collectExampleSettings(openRoot(t, dir))
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

// The root must refuse a path that escapes it, including through a
// symlink: the tool reads whatever the repository contains, and a
// repository is not always trusted.
func TestRootRefusesToEscape(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("SAFE_ZONE_SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}

	root := openRoot(t, dir)
	if _, err := collectExampleSettings(root); err == nil {
		t.Fatal("reading a symlink that points outside the root must fail")
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
