package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvironmentDefaultsToLocal(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "")
	if got := Environment(); got != "local" {
		t.Fatalf("expected local, got %q", got)
	}
	if IsProduction() {
		t.Fatal("expected non-production")
	}
}

func TestIsProductionSupportsAliases(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	if !IsProduction() {
		t.Fatal("expected production=true")
	}

	t.Setenv("SAFE_ZONE_ENV", "prod")
	if !IsProduction() {
		t.Fatal("expected prod alias to be production=true")
	}
}

func TestSecretStringEPrefersDirectEnv(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "from-env")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")

	got, err := SecretStringE("SAFE_ZONE_ADMIN_PASSWORD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "from-env" {
		t.Fatalf("expected from-env, got %q", got)
	}
}

func TestSecretStringEReadsFileAndTrimsWhitespace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(path, []byte("  file-secret \n"), 0o600); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", path)
	t.Setenv("SAFE_ZONE_SECRET_FILE_ROOT", dir)

	got, err := SecretStringE("SAFE_ZONE_ADMIN_PASSWORD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "file-secret" {
		t.Fatalf("expected trimmed file-secret, got %q", got)
	}
}

func TestSecretStringEReturnsErrorForUnreadableFile(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", filepath.Join(t.TempDir(), "missing.txt"))
	t.Setenv("SAFE_ZONE_SECRET_FILE_ROOT", t.TempDir())

	if _, err := SecretStringE("SAFE_ZONE_ADMIN_PASSWORD"); err == nil {
		t.Fatal("expected file read error")
	}
}
