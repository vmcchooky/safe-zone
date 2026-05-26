package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenWithinReadsRelativePath(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFileWithin(root, "secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("unexpected data %q", string(data))
	}
}

func TestOpenWithinRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	path := filepath.Join("..", filepath.Base(outside), "secret.txt")

	_, err := OpenWithin(root, path)
	if err == nil || !strings.Contains(err.Error(), "escapes safe root") {
		t.Fatalf("expected traversal rejection, got %v", err)
	}
}

func TestOpenWithinRejectsAbsoluteOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("nope"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := OpenWithin(root, outside)
	if err == nil || !strings.Contains(err.Error(), "escapes safe root") {
		t.Fatalf("expected absolute path rejection, got %v", err)
	}
}

func TestOpenWithinAcceptsRootPrefixedPath(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "nested", "secret.txt")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFileWithin(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("unexpected data %q", string(data))
	}
}
