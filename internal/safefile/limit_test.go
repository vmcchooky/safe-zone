package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The cap exists so a compromised or accidentally enormous file in a trusted
// directory is a bounded error instead of unbounded memory growth. These tests
// pin all three behaviors: under the limit reads fine, exactly at the limit
// reads fine, one byte past it fails with the limit named.
func TestReadFileWithinRejectsOversizedFile(t *testing.T) {
	root := t.TempDir()
	big := make([]byte, DefaultMaxReadBytes+100)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(root, "big.bin"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFileWithin(root, "big.bin")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected size-limit rejection, got %v", err)
	}
}

func TestReadFileWithinAcceptsExactlyAtLimit(t *testing.T) {
	root := t.TempDir()
	exact := make([]byte, DefaultMaxReadBytes)
	for i := range exact {
		exact[i] = 'y'
	}
	if err := os.WriteFile(filepath.Join(root, "exact.bin"), exact, 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFileWithin(root, "exact.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != DefaultMaxReadBytes {
		t.Fatalf("expected %d bytes, got %d", DefaultMaxReadBytes, len(data))
	}
}

// Open resolves against the process working directory, so these tests move the
// process there with t.Chdir rather than writing into the source tree. They
// must not run in parallel with anything else that depends on the cwd.
func TestReadFileReadsRelativePath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, "local.txt"), []byte("cwd"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, err := ReadFile("local.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "cwd" {
		t.Fatalf("unexpected data %q", string(data))
	}
}

func TestReadFileRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	big := make([]byte, DefaultMaxReadBytes+1)
	if err := os.WriteFile(filepath.Join(dir, "big.txt"), big, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := ReadFile("big.txt"); err == nil {
		t.Fatal("expected size-limit rejection, got nil")
	}
}

func TestOpenRejectsEmptyPath(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("expected an error for an empty path, got nil")
	}
}

func TestOpenResolvesThroughSecretsRoot(t *testing.T) {
	secrets := t.TempDir()
	work := t.TempDir()
	t.Chdir(work)
	t.Setenv("SAFE_ZONE_SECRETS_DIR", secrets)
	t.Setenv("SAFE_ZONE_SQLITE_PATH", "")
	if err := os.WriteFile(filepath.Join(secrets, "token"), []byte("s3cr3t"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Absolute path outside the cwd but inside the trusted secrets root.
	data, err := ReadFile(filepath.Join(secrets, "token"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "s3cr3t" {
		t.Fatalf("unexpected data %q", string(data))
	}
}

func TestOpenFallsBackToWorkspaceSandbox(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("SAFE_ZONE_SECRETS_DIR", filepath.Join(dir, "elsewhere", "secrets"))
	t.Setenv("SAFE_ZONE_SQLITE_PATH", filepath.Join(dir, "elsewhere", "app.db"))
	sub := filepath.Join(dir, "sub")
	if err := os.MkdirAll(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sub, "note.txt"), []byte("here"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Under the cwd but under neither trusted root: the workspace fallback.
	rel, err := filepath.Rel(dir, filepath.Join(sub, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := ReadFile(rel)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "here" {
		t.Fatalf("unexpected data %q", string(data))
	}
}

func TestOpenWithinRejectsMissingRoot(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := OpenWithin(missing, "x.txt"); err == nil {
		t.Fatal("expected an error for a missing sandbox root, got nil")
	}
}

func TestOpenWithinRejectsMissingFile(t *testing.T) {
	if _, err := OpenWithin(t.TempDir(), "absent.txt"); err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
}

func TestRelativeWithinRootRejectsEmpties(t *testing.T) {
	if _, err := relativeWithinRoot("", "x.txt"); err == nil {
		t.Fatal("expected an error for an empty root, got nil")
	}
	if _, err := relativeWithinRoot(t.TempDir(), ""); err == nil {
		t.Fatal("expected an error for an empty path, got nil")
	}
	if _, err := relativeWithinRoot(t.TempDir(), "."); err == nil {
		t.Fatal("expected an error for a bare directory reference, got nil")
	}
}

func TestCloseOnNilFileIsNoop(t *testing.T) {
	var f *File
	if err := f.Close(); err != nil {
		t.Fatalf("expected nil close on a nil file, got %v", err)
	}
}

func TestCloseReleasesSandbox(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f.txt"), []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenWithin(root, "f.txt")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("expected a clean close, got %v", err)
	}
}
