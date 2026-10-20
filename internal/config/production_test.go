package config

import (
	"strings"
	"testing"
)

func TestProductionGuardRequireEnv(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_REQUIRED", "")

	guard := NewGuard()
	guard.RequireEnv("SAFE_ZONE_TEST_REQUIRED")

	if !guard.HasProblems() {
		t.Fatal("expected an unset key to be reported")
	}
	if !strings.Contains(strings.Join(guard.Problems(), ";"), "SAFE_ZONE_TEST_REQUIRED") {
		t.Fatalf("problem should name the key, got %v", guard.Problems())
	}
}

func TestProductionGuardRequireEnvWhen(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_CONDITIONAL", "")

	guard := NewGuard()
	guard.RequireEnvWhen(false, "SAFE_ZONE_TEST_CONDITIONAL")
	if guard.HasProblems() {
		t.Fatalf("disabled condition must not report a problem, got %v", guard.Problems())
	}

	guard.RequireEnvWhen(true, "SAFE_ZONE_TEST_CONDITIONAL")
	if !guard.HasProblems() {
		t.Fatal("enabled condition must report a problem")
	}
}

func TestProductionGuardRequireIP(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_IP", "not-an-ip")

	guard := NewGuard()
	guard.RequireIP("SAFE_ZONE_TEST_IP")
	if !guard.HasProblems() {
		t.Fatal("expected a malformed IP to be reported")
	}

	t.Setenv("SAFE_ZONE_TEST_IP", "203.0.113.7")
	guard = NewGuard()
	guard.RequireIP("SAFE_ZONE_TEST_IP")
	if guard.HasProblems() {
		t.Fatalf("a valid IP must not be reported, got %v", guard.Problems())
	}
}

func TestProductionGuardRequireIPIgnoresUnset(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_IP", "")

	guard := NewGuard()
	guard.RequireIP("SAFE_ZONE_TEST_IP")
	if guard.HasProblems() {
		t.Fatalf("an unset IP must not be reported, got %v", guard.Problems())
	}
}

func TestProductionGuardRequireEnum(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_ENUM", "sinkhole")

	guard := NewGuard()
	guard.RequireEnum("SAFE_ZONE_TEST_ENUM", "sinkhole", "nxdomain")
	if guard.HasProblems() {
		t.Fatalf("an allowed value must not be reported, got %v", guard.Problems())
	}

	t.Setenv("SAFE_ZONE_TEST_ENUM", "drop-table")
	guard = NewGuard()
	guard.RequireEnum("SAFE_ZONE_TEST_ENUM", "sinkhole", "nxdomain")
	if !guard.HasProblems() {
		t.Fatal("expected a disallowed value to be reported")
	}
}

func TestProductionGuardRequireBoolAndInt(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_BOOL", "maybe")
	t.Setenv("SAFE_ZONE_TEST_INT", "many")

	guard := NewGuard()
	guard.RequireBool("SAFE_ZONE_TEST_BOOL")
	guard.RequireInt("SAFE_ZONE_TEST_INT")
	if len(guard.Problems()) != 2 {
		t.Fatalf("expected two problems, got %v", guard.Problems())
	}

	t.Setenv("SAFE_ZONE_TEST_BOOL", "true")
	t.Setenv("SAFE_ZONE_TEST_INT", "42")
	guard = NewGuard()
	guard.RequireBool("SAFE_ZONE_TEST_BOOL")
	guard.RequireInt("SAFE_ZONE_TEST_INT")
	if guard.HasProblems() {
		t.Fatalf("valid values must not be reported, got %v", guard.Problems())
	}
}

func TestProductionGuardErrDependsOnEnvironment(t *testing.T) {
	t.Setenv("SAFE_ZONE_TEST_REQUIRED", "")

	guard := NewGuard()
	guard.RequireEnv("SAFE_ZONE_TEST_REQUIRED")

	t.Setenv("SAFE_ZONE_ENV", "local")
	if err := guard.Err(); err != nil {
		t.Fatalf("local environment must not fail, got %v", err)
	}

	t.Setenv("SAFE_ZONE_ENV", "production")
	err := guard.Err()
	if err == nil {
		t.Fatal("production environment must fail on a collected problem")
	}
	if !strings.Contains(err.Error(), "SAFE_ZONE_TEST_REQUIRED") {
		t.Fatalf("error should name the key, got %v", err)
	}
}

func TestProductionGuardErrWithoutProblems(t *testing.T) {
	t.Setenv("SAFE_ZONE_ENV", "production")

	guard := NewGuard()
	if err := guard.Err(); err != nil {
		t.Fatalf("a guard without problems must not fail, got %v", err)
	}
}

func TestValidateIP(t *testing.T) {
	if _, err := ValidateIP("203.0.113.7"); err != nil {
		t.Fatalf("expected a valid IP, got %v", err)
	}
	if _, err := ValidateIP("2001:db8::1"); err != nil {
		t.Fatalf("expected a valid IPv6, got %v", err)
	}
	if _, err := ValidateIP(""); err == nil {
		t.Fatal("expected an empty value to fail")
	}
	if _, err := ValidateIP("127.0.0.999"); err == nil {
		t.Fatal("expected a malformed address to fail")
	}
}
