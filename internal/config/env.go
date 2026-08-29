package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"safe-zone/internal/safefile"
)

func String(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	return value
}

func Int(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return parsed
}

func DurationMillis(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return time.Duration(parsed) * time.Millisecond
}

func DurationSeconds(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}

	return time.Duration(parsed) * time.Second
}

func Bool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	}
	return fallback
}

func Float64(key string, fallback float64) float64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func Environment() string {
	value := strings.ToLower(strings.TrimSpace(os.Getenv("SAFE_ZONE_ENV")))
	if value == "" {
		return "local"
	}
	return value
}

// NormalizeEnvironment validates a SAFE_ZONE_ENV value. Service binaries with
// a security surface (core-api) refuse to start on an empty or unsupported
// value so the security profile is always explicit; "prod" normalizes to
// "production".
func NormalizeEnvironment(value string) (string, error) {
	switch env := strings.ToLower(strings.TrimSpace(value)); env {
	case "local", "test", "development", "production":
		return env, nil
	case "prod":
		return "production", nil
	case "":
		return "", fmt.Errorf("SAFE_ZONE_ENV is required; set one of local, test, development, production")
	default:
		return "", fmt.Errorf("unsupported SAFE_ZONE_ENV %q; use one of local, test, development, production", value)
	}
}

// EnvironmentAllowsGeneratedSecrets reports whether the profile may generate
// temporary local-only admin credentials.
func EnvironmentAllowsGeneratedSecrets(env string) bool {
	return env == "local" || env == "test"
}

// EnvironmentRequiresValidatedSecrets reports whether the profile fails fast
// on missing or weak admin secrets.
func EnvironmentRequiresValidatedSecrets(env string) bool {
	return env == "production" || env == "development"
}

func SecretFileRoot() string {
	return String("SAFE_ZONE_SECRET_FILE_ROOT", "./ops/secrets")
}

func FeedFileRoot() string {
	return String("SAFE_ZONE_FEED_FILE_ROOT", "./data")
}

func ConfigFileRoot() string {
	return String("SAFE_ZONE_CONFIG_FILE_ROOT", "./data")
}

func IsProduction() bool {
	switch Environment() {
	case "production", "prod":
		return true
	default:
		return false
	}
}

func SecretString(key, fallback string) string {
	value, err := SecretStringE(key)
	if err != nil || value == "" {
		return fallback
	}
	return value
}

func SecretStringE(key string) (string, error) {
	if value := os.Getenv(key); value != "" {
		return value, nil
	}

	fileKey := key + "_FILE"
	filePath := strings.TrimSpace(os.Getenv(fileKey))
	if filePath == "" {
		return "", nil
	}

	data, err := safefile.ReadFileWithin(SecretFileRoot(), filePath)
	if err != nil {
		return "", fmt.Errorf("read %s from %s: %w", fileKey, filePath, err)
	}

	return strings.TrimSpace(string(data)), nil
}
