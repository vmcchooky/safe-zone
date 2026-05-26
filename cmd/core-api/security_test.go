package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRuntimeSecurityProductionRequiresSecrets(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "SAFE_ZONE_ADMIN_PASSWORD") {
		t.Fatalf("expected production password error, got %v", err)
	}
}

func TestLoadRuntimeSecurityProductionRejectsWeakSecrets(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "change-me")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "short")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "SAFE_ZONE_ADMIN_PASSWORD") {
		t.Fatalf("expected weak password error, got %v", err)
	}
}

func TestLoadRuntimeSecurityProductionAcceptsFileSecrets(t *testing.T) {
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "admin_password")
	apiKeyFile := filepath.Join(dir, "admin_api_key")

	if err := os.WriteFile(passwordFile, []byte("StrongPassword-2026!"), 0o600); err != nil {
		t.Fatalf("write password secret: %v", err)
	}
	if err := os.WriteFile(apiKeyFile, []byte("0123456789abcdef0123456789abcdef"), 0o600); err != nil {
		t.Fatalf("write api key secret: %v", err)
	}

	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", passwordFile)
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", apiKeyFile)
	t.Setenv("SAFE_ZONE_SECRET_FILE_ROOT", dir)

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if security.adminPassword != "StrongPassword-2026!" {
		t.Fatalf("unexpected admin password %q", security.adminPassword)
	}
	if security.adminAPIKey != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected api key %q", security.adminAPIKey)
	}
	if len(security.sessionSecret) == 0 {
		t.Fatal("expected session secret")
	}
}

func TestLoadRuntimeSecurityLocalGeneratesFallbacks(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if security.adminPassword == "" {
		t.Fatal("expected generated admin password")
	}
	if security.adminAPIKey == "" {
		t.Fatal("expected generated admin api key")
	}
	if len(security.sessionSecret) == 0 {
		t.Fatal("expected generated session secret")
	}

	content, err := os.ReadFile(localAdminSecretsFile)
	if err != nil {
		t.Fatalf("expected local admin secrets file: %v", err)
	}
	body := string(content)
	if !strings.Contains(body, "SAFE_ZONE_ADMIN_PASSWORD="+security.adminPassword+"\n") {
		t.Fatal("expected generated admin password in local secrets file")
	}
	if !strings.Contains(body, "SAFE_ZONE_ADMIN_API_KEY="+security.adminAPIKey+"\n") {
		t.Fatal("expected generated admin api key in local secrets file")
	}
}
