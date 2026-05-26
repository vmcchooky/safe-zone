package main

import (
	"fmt"
	"os"
	"strings"

	"safe-zone/internal/auth"
	"safe-zone/internal/config"
	"safe-zone/internal/logjson"
)

const (
	generatedSessionSecretBytes = 32
	generatedAdminPasswordBytes = 16
	generatedAdminAPIKeyBytes   = 24
	minAdminPasswordLength      = 12
	minAdminAPIKeyLength        = 24
	localAdminSecretsDir        = "tmp"
	localAdminSecretsFile       = "tmp/local_admin_secrets.txt" // #nosec G101 -- file path only, not an embedded credential.
)

type runtimeSecurity struct {
	sessionSecret []byte
	adminPassword string
	adminAPIKey   string
}

func loadRuntimeSecurity() (runtimeSecurity, error) {
	sessionSeed, err := auth.GenerateSecureRandomString(generatedSessionSecretBytes)
	if err != nil {
		return runtimeSecurity{}, fmt.Errorf("generate session secret: %w", err)
	}

	adminPassword, err := config.SecretStringE("SAFE_ZONE_ADMIN_PASSWORD")
	if err != nil {
		return runtimeSecurity{}, err
	}
	adminAPIKey, err := config.SecretStringE("SAFE_ZONE_ADMIN_API_KEY")
	if err != nil {
		return runtimeSecurity{}, err
	}

	if config.IsProduction() {
		if err := validateProductionAdminPassword(adminPassword); err != nil {
			return runtimeSecurity{}, err
		}
		if err := validateProductionAdminAPIKey(adminAPIKey); err != nil {
			return runtimeSecurity{}, err
		}
		return runtimeSecurity{
			sessionSecret: []byte(sessionSeed),
			adminPassword: adminPassword,
			adminAPIKey:   adminAPIKey,
		}, nil
	}

	generatedAdminPassword := ""
	generatedAdminAPIKey := ""

	if adminPassword == "" {
		adminPassword, err = auth.GenerateSecureRandomString(generatedAdminPasswordBytes)
		if err != nil {
			return runtimeSecurity{}, fmt.Errorf("generate admin password: %w", err)
		}
		generatedAdminPassword = adminPassword
		logjson.Warn("generated temporary local-only admin password", map[string]any{
			"service":        "core-api",
			"config_key":     "SAFE_ZONE_ADMIN_PASSWORD",
			"generated_only": true,
		})
	} else if err := validateProductionAdminPassword(adminPassword); err != nil {
		logjson.Warn("admin password validation warning", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
	}

	if adminAPIKey == "" {
		adminAPIKey, err = auth.GenerateSecureRandomString(generatedAdminAPIKeyBytes)
		if err != nil {
			return runtimeSecurity{}, fmt.Errorf("generate admin API key: %w", err)
		}
		generatedAdminAPIKey = adminAPIKey
		logjson.Warn("generated temporary local-only admin api key", map[string]any{
			"service":        "core-api",
			"config_key":     "SAFE_ZONE_ADMIN_API_KEY",
			"generated_only": true,
		})
	} else if err := validateProductionAdminAPIKey(adminAPIKey); err != nil {
		logjson.Warn("admin api key validation warning", map[string]any{
			"service": "core-api",
			"error":   err.Error(),
		})
	}

	if generatedAdminPassword != "" || generatedAdminAPIKey != "" {
		if err := writeLocalAdminSecrets(generatedAdminPassword, generatedAdminAPIKey); err != nil {
			return runtimeSecurity{}, err
		}
		logjson.Warn("temporary local-only admin secrets generated and saved to file", map[string]any{
			"service":      "core-api",
			"secrets_file": localAdminSecretsFile,
		})
	}

	return runtimeSecurity{
		sessionSecret: []byte(sessionSeed),
		adminPassword: adminPassword,
		adminAPIKey:   adminAPIKey,
	}, nil
}

func writeLocalAdminSecrets(adminPassword, adminAPIKey string) error {
	var content strings.Builder
	if adminPassword != "" {
		content.WriteString("SAFE_ZONE_ADMIN_PASSWORD=")
		content.WriteString(adminPassword)
		content.WriteString("\n")
	}
	if adminAPIKey != "" {
		content.WriteString("SAFE_ZONE_ADMIN_API_KEY=")
		content.WriteString(adminAPIKey)
		content.WriteString("\n")
	}

	if err := os.MkdirAll(localAdminSecretsDir, 0o750); err != nil {
		return fmt.Errorf("create local admin secrets directory: %w", err)
	}
	if err := os.WriteFile(localAdminSecretsFile, []byte(content.String()), 0o600); err != nil {
		return fmt.Errorf("write local admin secrets file: %w", err)
	}
	return nil
}

func validateProductionAdminPassword(password string) error {
	password = strings.TrimSpace(password)
	if password == "" {
		return fmt.Errorf("SAFE_ZONE_ADMIN_PASSWORD or SAFE_ZONE_ADMIN_PASSWORD_FILE is required when SAFE_ZONE_ENV=%s", config.Environment())
	}
	if len(password) < minAdminPasswordLength {
		return fmt.Errorf("SAFE_ZONE_ADMIN_PASSWORD is too weak: need at least %d characters", minAdminPasswordLength)
	}
	if looksPlaceholderSecret(password) {
		return fmt.Errorf("SAFE_ZONE_ADMIN_PASSWORD uses a placeholder-style value; replace it with a real secret")
	}
	return nil
}

func validateProductionAdminAPIKey(apiKey string) error {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return fmt.Errorf("SAFE_ZONE_ADMIN_API_KEY or SAFE_ZONE_ADMIN_API_KEY_FILE is required when SAFE_ZONE_ENV=%s", config.Environment())
	}
	if len(apiKey) < minAdminAPIKeyLength {
		return fmt.Errorf("SAFE_ZONE_ADMIN_API_KEY is too short: need at least %d characters", minAdminAPIKeyLength)
	}
	if looksPlaceholderSecret(apiKey) {
		return fmt.Errorf("SAFE_ZONE_ADMIN_API_KEY uses a placeholder-style value; replace it with a real secret")
	}
	return nil
}

func looksPlaceholderSecret(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer("-", "", "_", "", " ", "")
	normalized = replacer.Replace(normalized)

	if normalized == "" {
		return true
	}

	exactPlaceholders := []string{
		"password",
		"adminpassword",
		"apikey",
		"token",
		"secret",
		"testkey",
		"testpass",
		"example",
		"sample",
		"placeholder",
	}

	for _, marker := range exactPlaceholders {
		if normalized == marker {
			return true
		}
	}

	patternPlaceholders := []string{
		"changeme",
		"replacewith",
		"your",
	}

	for _, marker := range patternPlaceholders {
		if strings.HasPrefix(normalized, marker) || strings.Contains(normalized, marker) {
			return true
		}
	}

	return false
}
