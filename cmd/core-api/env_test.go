package main

import (
	"os"
	"strings"
	"testing"
)

// An empty SAFE_ZONE_ENV must refuse to start instead of silently falling
// back to lenient local behavior.
func TestLoadRuntimeSecurityRejectsEmptyEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "SAFE_ZONE_ENV is required") {
		t.Fatalf("expected empty environment rejection, got %v", err)
	}
	if _, statErr := os.Stat(localAdminSecretsFile); statErr == nil {
		t.Fatal("no local secrets file may be created without an explicit environment")
	}
}

func TestLoadRuntimeSecurityRejectsUnknownEnvironment(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "staging")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "unsupported SAFE_ZONE_ENV") {
		t.Fatalf("expected unknown environment rejection, got %v", err)
	}
	if _, statErr := os.Stat(localAdminSecretsFile); statErr == nil {
		t.Fatal("no local secrets file may be created for an unknown environment")
	}
}

// The development profile requires real secrets (no generated credentials,
// no secrets file) while staying non-production elsewhere.
func TestLoadRuntimeSecurityDevelopmentRequiresSecrets(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "development")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "SAFE_ZONE_ADMIN_PASSWORD") {
		t.Fatalf("expected development password requirement, got %v", err)
	}
	if _, statErr := os.Stat(localAdminSecretsFile); statErr == nil {
		t.Fatal("no local secrets file may be created in development")
	}
}

// The test profile behaves like local: temporary credentials may be
// generated for disposable environments.
func TestLoadRuntimeSecurityTestAllowsGeneratedSecrets(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "test")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if security.adminPasswordHash == "" {
		t.Fatal("expected generated admin password hash")
	}
	if _, statErr := os.Stat(localAdminSecretsFile); statErr != nil {
		t.Fatal("expected local secrets file for the test profile")
	}
}
