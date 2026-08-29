package main

import (
	"os"
	"strings"
	"testing"

	"safe-zone/internal/auth"
)

// The bcrypt input limit is 72 BYTES (not runes) and is enforced for every
// environment profile before hashing; the error must not echo the secret.
func TestLoadRuntimeSecurityAcceptsPasswordAtByteLimit(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")

	exactlyLimit := strings.Repeat("a", 72)
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", exactlyLimit)

	security, err := loadRuntimeSecurity()
	if err != nil {
		t.Fatalf("expected 72-byte password to be accepted, got %v", err)
	}
	if err := auth.VerifyPasswordHash(security.adminPasswordHash, exactlyLimit); err != nil {
		t.Fatalf("loaded hash must verify against the exact 72-byte password: %v", err)
	}
}

func TestLoadRuntimeSecurityRejectsPasswordOverByteLimit(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")

	overLimit := strings.Repeat("b", 73)
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", overLimit)
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")

	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "at most 72 bytes") {
		t.Fatalf("expected 73-byte password rejection, got %v", err)
	}
	if strings.Contains(err.Error(), overLimit) {
		t.Fatal("the rejection must not echo the secret")
	}
}

// Multibyte characters count per byte: 36 two-byte runes land exactly on the
// 72-byte limit, 37 runes exceed it.
func TestLoadRuntimeSecurityCountsMultibytePasswordsInBytes(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "local")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")

	exactlyLimit := strings.Repeat("é", 36) // 36 runes × 2 bytes = 72 bytes
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", exactlyLimit)
	if _, err := loadRuntimeSecurity(); err != nil {
		t.Fatalf("expected 72-byte multibyte password to be accepted, got %v", err)
	}

	overLimit := strings.Repeat("é", 37) // 74 bytes
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", overLimit)
	_, err := loadRuntimeSecurity()
	if err == nil || !strings.Contains(err.Error(), "at most 72 bytes") {
		t.Fatalf("expected 74-byte multibyte password rejection, got %v", err)
	}
	if strings.Contains(err.Error(), overLimit) {
		t.Fatal("the rejection must not echo the secret")
	}
}

// The byte limit holds in strict profiles too (before secret-strength rules
// would even run, an oversized password is reported with the same contract).
func TestLoadRuntimeSecurityByteLimitAppliesInProduction(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("SAFE_ZONE_ENV", "production")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("SAFE_ZONE_ADMIN_API_KEY_FILE", "")
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD_FILE", "")

	overLimit := strings.Repeat("c", 73)
	t.Setenv("SAFE_ZONE_ADMIN_PASSWORD", overLimit)

	_, err := loadRuntimeSecurity()
	if err == nil {
		t.Fatal("expected production startup failure for an oversized password")
	}
	if _, statErr := os.Stat(localAdminSecretsFile); statErr == nil {
		t.Fatal("no local secrets file may be created in production")
	}
}
