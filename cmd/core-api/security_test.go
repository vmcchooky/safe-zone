package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"safe-zone/internal/auth"
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

func TestLooksPlaceholderSecretRejectsShippedDevDefaults(t *testing.T) {
	// These exact strings shipped in start.bat in git history. They clear
	// the length checks, so the placeholder gate is the only thing that
	// can stop an operator from promoting a dev .env to production.
	for _, value := range []string{
		"SafeRoadLocalAdmin123!",
		"SafeRoadLocalApiKey1234567890",
		"saferoad-anything-else-99",
	} {
		if !looksPlaceholderSecret(value) {
			t.Fatalf("looksPlaceholderSecret(%q) = false, want true", value)
		}
	}
	for _, value := range []string{
		"StrongPassword-2026!",
		"0123456789abcdef0123456789abcdef",
	} {
		if looksPlaceholderSecret(value) {
			t.Fatalf("looksPlaceholderSecret(%q) = true, want false", value)
		}
	}
}

func TestLoadRuntimeSecurityProductionRejectsShippedDevDefaults(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "SafeRoadLocalAdmin123!")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "SafeRoadLocalApiKey1234567890")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Fatalf("expected placeholder-style secret error, got %v", err)
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
	if security.adminPasswordHash == "" {
		t.Fatal("expected admin password hash")
	}
	if err := auth.VerifyPasswordHash(security.adminPasswordHash, "StrongPassword-2026!"); err != nil {
		t.Fatalf("hash must verify against the configured password: %v", err)
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
	if security.adminPasswordHash == "" {
		t.Fatal("expected generated admin password hash")
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
	var filePassword, fileAPIKey string
	for _, line := range strings.Split(string(content), "\n") {
		if value, ok := strings.CutPrefix(line, "SAFE_ZONE_ADMIN_PASSWORD="); ok {
			filePassword = value
		}
		if value, ok := strings.CutPrefix(line, "SAFE_ZONE_ADMIN_API_KEY="); ok {
			fileAPIKey = value
		}
	}
	if filePassword == "" || auth.VerifyPasswordHash(security.adminPasswordHash, filePassword) != nil {
		t.Fatal("local secrets file must contain the generated password matching the loaded hash")
	}
	if fileAPIKey == "" || fileAPIKey != security.adminAPIKey {
		t.Fatal("expected generated admin api key in local secrets file")
	}
}

func readGeneratedAdminSecrets(t *testing.T) map[string]string {
	t.Helper()
	content, err := os.ReadFile(localAdminSecretsFile)
	if err != nil {
		t.Fatalf("read local admin secrets file: %v", err)
	}
	secrets := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && value != "" {
			secrets[key] = value
		}
	}
	return secrets
}

func TestLoadRuntimeSecurityLocalReusesGeneratedSecrets(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	first, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("first start: %v", err)
	}
	stored := readGeneratedAdminSecrets(t)
	storedPassword := stored[localAdminPasswordKey]
	if storedPassword == "" || stored[localAdminAPIKeyKey] == "" {
		t.Fatalf("first start must persist both generated secrets, got %d keys", len(stored))
	}

	second, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if second.adminAPIKey != first.adminAPIKey {
		t.Fatal("api key must not rotate when the generated secrets file survives")
	}
	if err := auth.VerifyPasswordHash(second.adminPasswordHash, storedPassword); err != nil {
		t.Fatalf("second start must keep the generated password: %v", err)
	}
}

func TestLoadRuntimeSecurityLocalPreservesReusedSecretWhenGeneratingTheOther(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	const storedPassword = "0123456789abcdef0123456789abcdef"
	if err := os.MkdirAll(localAdminSecretsDir, 0o750); err != nil {
		t.Fatalf("create secrets dir: %v", err)
	}
	seed := localAdminPasswordKey + "=" + storedPassword + "\n"
	if err := os.WriteFile(localAdminSecretsFile, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed secrets file: %v", err)
	}

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := auth.VerifyPasswordHash(security.adminPasswordHash, storedPassword); err != nil {
		t.Fatalf("stored password must remain effective: %v", err)
	}

	stored := readGeneratedAdminSecrets(t)
	if stored[localAdminPasswordKey] != storedPassword {
		t.Fatal("rewriting the secrets file must preserve the reused password")
	}
	if stored[localAdminAPIKeyKey] == "" || stored[localAdminAPIKeyKey] != security.adminAPIKey {
		t.Fatal("secrets file must contain the newly generated api key")
	}
}

func TestLoadRuntimeSecurityLocalHonoursExplicitSecretFile(t *testing.T) {
	t.Chdir(t.TempDir())
	dir := t.TempDir()
	passwordFile := filepath.Join(dir, "admin_password")
	if err := os.WriteFile(passwordFile, nil, 0o600); err != nil {
		t.Fatalf("write empty password file: %v", err)
	}

	const storedPassword = "0123456789abcdef0123456789abcdef"
	if err := os.MkdirAll(localAdminSecretsDir, 0o750); err != nil {
		t.Fatalf("create secrets dir: %v", err)
	}
	seed := localAdminPasswordKey + "=" + storedPassword + "\n"
	if err := os.WriteFile(localAdminSecretsFile, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed secrets file: %v", err)
	}

	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_SECRET_FILE_ROOT", dir)
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", passwordFile)
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth.VerifyPasswordHash(security.adminPasswordHash, storedPassword) == nil {
		t.Fatal("an explicitly configured password file must not fall back to the generated secret")
	}
	if stored := readGeneratedAdminSecrets(t); stored[localAdminPasswordKey] == storedPassword {
		t.Fatal("the generated secrets file must not keep advertising a superseded password")
	}
}
