package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// ProductionGuard collects configuration problems that must stop a service
// from starting in production.
//
// The rule is deliberately narrow: a problem is only reported when the
// operator explicitly configured something and that value cannot work. A
// setting that is simply absent is not a problem — an operator who never
// asked for a whitelist, a DoT certificate or a threat feed does not get a
// service that refuses to boot.
//
// Outside production the guard still collects and reports problems, but they
// are warnings: a local or test run must not fail because a production-only
// knob is unset.
type ProductionGuard struct {
	problems []string
}

// NewGuard returns an empty guard.
func NewGuard() *ProductionGuard {
	return &ProductionGuard{}
}

// RequireEnv reports a problem when key is unset or empty.
func (g *ProductionGuard) RequireEnv(key string) {
	if g == nil {
		return
	}
	if strings.TrimSpace(os.Getenv(key)) == "" {
		g.problems = append(g.problems, fmt.Sprintf("%s is not set", key))
	}
}

// RequireEnvWhen reports a problem when key is unset or empty and condition
// is true. Use it for settings that only matter once another feature is on.
func (g *ProductionGuard) RequireEnvWhen(condition bool, key string) {
	if !condition {
		return
	}
	g.RequireEnv(key)
}

// RequireIP reports a problem when key is set to a value that is not a valid
// IP address. An unset key is left alone: the caller decides whether the
// default is acceptable.
func (g *ProductionGuard) RequireIP(key string) {
	if g == nil {
		return
	}
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	if net.ParseIP(value) == nil {
		g.problems = append(g.problems, fmt.Sprintf("%s=%q is not a valid IP address", key, value))
	}
}

// RequireEnum reports a problem when key is set to a value outside allowed.
func (g *ProductionGuard) RequireEnum(key string, allowed ...string) {
	if g == nil {
		return
	}
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	for _, candidate := range allowed {
		if strings.EqualFold(value, candidate) {
			return
		}
	}
	g.problems = append(g.problems, fmt.Sprintf("%s=%q is not one of %s", key, value, strings.Join(allowed, ", ")))
}

// RequireBool reports a problem when key is set to a value that is not a
// recognised boolean literal. config.Bool silently falls back to its default
// for an unrecognised value, which hides a typo behind working defaults.
func (g *ProductionGuard) RequireBool(key string) {
	if g == nil {
		return
	}
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	switch strings.ToLower(value) {
	case "1", "true", "yes", "on", "0", "false", "no", "off":
		return
	}
	g.problems = append(g.problems, fmt.Sprintf("%s=%q is not a boolean literal", key, value))
}

// RequireInt reports a problem when key is set to a value that is not an
// integer. config.Int silently falls back to its default for an
// unparseable value.
func (g *ProductionGuard) RequireInt(key string) {
	if g == nil {
		return
	}
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return
	}
	if _, err := strconv.Atoi(value); err != nil {
		g.problems = append(g.problems, fmt.Sprintf("%s=%q is not an integer", key, value))
	}
}

// AddProblem records an arbitrary configuration problem.
func (g *ProductionGuard) AddProblem(format string, args ...any) {
	if g == nil {
		return
	}
	g.problems = append(g.problems, fmt.Sprintf(format, args...))
}

// Problems returns every collected problem, in the order it was found.
func (g *ProductionGuard) Problems() []string {
	if g == nil {
		return nil
	}
	return append([]string(nil), g.problems...)
}

// HasProblems reports whether any problem was collected.
func (g *ProductionGuard) HasProblems() bool {
	return g != nil && len(g.problems) > 0
}

// Err returns an aggregated error when the guard collected problems and the
// environment requires validated configuration. Outside production it
// returns nil so a local or test run keeps working.
func (g *ProductionGuard) Err() error {
	if !g.HasProblems() {
		return nil
	}
	if !EnvironmentRequiresValidatedSecrets(Environment()) {
		return nil
	}
	return fmt.Errorf("invalid production configuration: %s", strings.Join(g.problems, "; "))
}

// ValidateIP parses an IP address, returning an error instead of the silent
// nil that net.ParseIP returns for a malformed value.
func ValidateIP(value string) (net.IP, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, fmt.Errorf("IP address is empty")
	}
	parsed := net.ParseIP(trimmed)
	if parsed == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", value)
	}
	return parsed, nil
}
