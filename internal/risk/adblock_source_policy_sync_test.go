package risk

import (
	"context"
	"testing"

	"safe-zone/internal/domaintrie"
)

// The fingerprint is the divergence detector: two processes holding identical
// configuration must produce the same value, and any real difference must change
// it. If map iteration order leaked into the digest, every process would report a
// different value and the check would be useless noise.
func TestSourcePolicyFingerprintIsStableAndSensitive(t *testing.T) {
	a := adblockSourcePolicySet{
		"https://example.test/one": {Category: "ads", Scope: "suffix"},
		"https://example.test/two": {Category: "tracking", Scope: "exact"},
	}
	// Same content, built in a different insertion order.
	b := adblockSourcePolicySet{}
	b["https://example.test/two"] = adblockSourcePolicy{Category: "tracking", Scope: "exact"}
	b["https://example.test/one"] = adblockSourcePolicy{Category: "ads", Scope: "suffix"}

	if adblockSourcePoliciesFingerprint(a) != adblockSourcePoliciesFingerprint(b) {
		t.Fatal("identical policy sets must fingerprint identically regardless of insertion order")
	}
	for i := 0; i < 20; i++ {
		if adblockSourcePoliciesFingerprint(a) != adblockSourcePoliciesFingerprint(b) {
			t.Fatalf("fingerprint varied across iterations at %d", i)
		}
	}

	changed := []adblockSourcePolicySet{
		{},
		{"https://example.test/one": {Category: "tracking", Scope: "suffix"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
		{"https://example.test/one": {Category: "ads", Scope: "exact"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
		{"https://example.test/one": {Category: "ads", Scope: "suffix"}},
		{"https://example.test/THREE": {Category: "ads", Scope: "suffix"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
	}
	base := adblockSourcePoliciesFingerprint(a)
	for i, set := range changed {
		if adblockSourcePoliciesFingerprint(set) == base {
			t.Fatalf("case %d must not share the baseline fingerprint", i)
		}
	}

	// An empty set still has a comparable digest, so "no policies" is a value
	// that can be compared rather than an absent field.
	if adblockSourcePoliciesFingerprint(nil) != adblockSourcePoliciesFingerprint(adblockSourcePolicySet{}) {
		t.Fatal("a nil set and an empty set must digest identically")
	}
}

// A change must request a rebuild, because category and scope are stamped onto
// rules at parse time: publishing a policy without rebuilding would store a
// policy that is not in force.
func TestSetAdblockSourcePoliciesRequestsRebuildOnChange(t *testing.T) {
	svc, _ := newAdblockControlService(t)
	svc.adblock.adblockResync = make(chan struct{}, 1)
	svc.adblock.adblockSourcePolicies.Store(&adblockSourcePolicySet{})

	svc.adblock.SetAdblockSourcePolicies(parseAdblockSourcePolicies(
		`{"https://a.test/x":{"category":"ads","scope":"suffix"}}`))

	select {
	case <-svc.adblock.adblockResync:
	default:
		t.Fatal("a policy change must request a rule rebuild")
	}
	if got := svc.adblock.currentAdblockSourcePolicies()["https://a.test/x"]; got.Category != "ads" {
		t.Fatalf("policy not published: %+v", got)
	}

	// Re-applying the same policy is a no-op and must not queue another rebuild,
	// otherwise the periodic refresh would rebuild the trie every 30 seconds.
	select {
	case <-svc.adblock.adblockResync:
	default:
	}
	svc.adblock.SetAdblockSourcePolicies(parseAdblockSourcePolicies(
		`{"https://a.test/x":{"category":"ads","scope":"suffix"}}`))
	select {
	case <-svc.adblock.adblockResync:
		t.Fatal("an unchanged policy must not request a rebuild")
	default:
	}

	// A real change does rebuild.
	svc.adblock.SetAdblockSourcePolicies(parseAdblockSourcePolicies(
		`{"https://a.test/x":{"category":"tracking","scope":"suffix"}}`))
	select {
	case <-svc.adblock.adblockResync:
	default:
		t.Fatal("a changed policy must request a rebuild")
	}
}

// The store must beat the environment, exactly like the enable flag and the
// match mode. This is the property that makes an operator change survive the next
// refresh instead of being silently reverted.
func TestRefreshAdblockSourcePoliciesPrefersStoreOverEnv(t *testing.T) {
	svc, storeDB := newAdblockControlService(t)
	t.Setenv(envAdblockSourcePoliciesJSON,
		`{"https://a.test/x":{"category":"ads","scope":"suffix"}}`)

	// Environment alone.
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	if got := svc.adblock.currentAdblockSourcePolicies()["https://a.test/x"]; got.Category != "ads" {
		t.Fatalf("expected the environment policy to apply, got %+v", got)
	}

	// Operator overrides through the store.
	if err := storeDB.SetSystemConfig(context.Background(), systemConfigAdblockSourcePolicies,
		`{"https://a.test/x":{"category":"telemetry","scope":"exact"}}`); err != nil {
		t.Fatalf("persist policy: %v", err)
	}
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	got := svc.adblock.currentAdblockSourcePolicies()["https://a.test/x"]
	if got.Category != "telemetry" || got.Scope != "exact" {
		t.Fatalf("store must win over the environment, got %+v", got)
	}

	// The resolved rule must reflect it, not just the cached set.
	category, scope, _ := svc.adblock.resolveAdblockSourcePolicy("https://a.test/x")
	if category != "telemetry" || scope != domaintrie.RuleScopeExact {
		t.Fatalf("rule resolution must use the store policy, got category=%q scope=%q", category, scope)
	}
}

// Status must expose the digest so the two processes can be compared, and an
// empty configuration must still report a comparable value.
func TestAdblockStatusExposesSourcePolicyFingerprint(t *testing.T) {
	svc, _ := newAdblockControlService(t)
	svc.adblock.adblockSourcePolicies.Store(&adblockSourcePolicySet{})

	empty := svc.adblock.AdblockStatus()
	if empty.SourcePoliciesFingerprint == "" {
		t.Fatal("an empty policy set must still report a comparable fingerprint")
	}
	if empty.SourcePolicyCount != 0 {
		t.Fatalf("expected zero policies, got %d", empty.SourcePolicyCount)
	}

	svc.adblock.SetAdblockSourcePolicies(parseAdblockSourcePolicies(
		`{"https://a.test/x":{"category":"ads","scope":"suffix"}}`))
	populated := svc.adblock.AdblockStatus()
	if populated.SourcePoliciesFingerprint == empty.SourcePoliciesFingerprint {
		t.Fatal("the fingerprint must change when policies change")
	}
	if populated.SourcePolicyCount != 1 {
		t.Fatalf("expected one policy, got %d", populated.SourcePolicyCount)
	}
}

func TestAdblockSourcePoliciesFingerprintIsStableAndSensitive(t *testing.T) {
	a := adblockSourcePolicySet{
		"https://example.test/one": {Category: "ads", Scope: "suffix"},
		"https://example.test/two": {Category: "tracking", Scope: "exact"},
	}
	// Same content, built in a different insertion order.
	b := adblockSourcePolicySet{}
	b["https://example.test/two"] = adblockSourcePolicy{Category: "tracking", Scope: "exact"}
	b["https://example.test/one"] = adblockSourcePolicy{Category: "ads", Scope: "suffix"}

	if adblockSourcePoliciesFingerprint(a) != adblockSourcePoliciesFingerprint(b) {
		t.Fatal("identical policy sets must fingerprint identically regardless of insertion order")
	}
	for i := 0; i < 20; i++ {
		if adblockSourcePoliciesFingerprint(a) != adblockSourcePoliciesFingerprint(b) {
			t.Fatalf("fingerprint varied across iterations at %d", i)
		}
	}

	changed := []adblockSourcePolicySet{
		{},
		{"https://example.test/one": {Category: "tracking", Scope: "suffix"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
		{"https://example.test/one": {Category: "ads", Scope: "exact"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
		{"https://example.test/one": {Category: "ads", Scope: "suffix"}},
		{"https://example.test/THREE": {Category: "ads", Scope: "suffix"}, "https://example.test/two": {Category: "tracking", Scope: "exact"}},
	}
	base := adblockSourcePoliciesFingerprint(a)
	for i, set := range changed {
		if adblockSourcePoliciesFingerprint(set) == base {
			t.Fatalf("case %d must not share the baseline fingerprint", i)
		}
	}

	// An empty set still has a comparable digest, so "no policies" is a value
	// that can be compared rather than an absent field.
	if adblockSourcePoliciesFingerprint(nil) != adblockSourcePoliciesFingerprint(adblockSourcePolicySet{}) {
		t.Fatal("a nil set and an empty set must digest identically")
	}
}
