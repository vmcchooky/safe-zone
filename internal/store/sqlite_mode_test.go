package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The database holds session fingerprints, client IPs and operator policy,
// so the file must be owner-only. Default umask would leave it world-readable.
func TestNewRestrictsDatabaseFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mode.db")
	db, err := New(path, 30)
	if err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatalf("close db: %v", err)
		}
	})
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if runtime.GOOS == "windows" {
		// Windows ACLs do not express Unix mode bits; os.Chmod is a
		// near-no-op there, so only existence is asserted on Windows.
		// The mode guarantee is enforced (and tested) on Unix hosts,
		// which is where self-hosted production runs.
		return
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("database file mode = %o, want 600", perm)
	}
}
