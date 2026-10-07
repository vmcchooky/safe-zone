package risk

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// One source string must have exactly one identity everywhere: the policy
// fingerprint, the policy lookup, the per-source download cache and the rule
// provenance digest. Before this, the fingerprint and provenance used the
// canonical key while the lookup and the cache path used the raw string, so a
// pure case change hashed the same for change detection but produced two cache
// files, and SetAdblockSourcePolicies deduped it as "no change" and never
// published it.
func TestSourceIdentityIsCanonicalEverywhere(t *testing.T) {
	svc, _ := newPolicyService(t)

	spellings := []string{
		"https://Example.com/hosts",
		"HTTPS://example.com/hosts",
		"https://example.com/hosts",
	}

	// One identity: the same cache path and the same provenance digest.
	first := svc.adblock.adblockSourceCachePath(spellings[0])
	firstID := canonicalSourceID(spellings[0])
	for _, spelling := range spellings[1:] {
		if got := svc.adblock.adblockSourceCachePath(spelling); got != first {
			t.Fatalf("cache path for %q = %q, want the same identity as %q (%q)", spelling, got, spellings[0], first)
		}
		if got := canonicalSourceID(spelling); got != firstID {
			t.Fatalf("provenance digest for %q = %q, want %q", spelling, got, firstID)
		}
	}

	// A policy written under one spelling must be found under another.
	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://Example.com/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}
	for _, spelling := range spellings {
		category, scope, origin := svc.adblock.resolveAdblockSourcePolicy(spelling)
		if category != "ads" || scope != domaintrie.RuleScopeExact || origin != domaintrie.OriginSourcePolicyExact {
			t.Fatalf("lookup for %q = category %q scope %q origin %q, want the policy", spelling, category, scope, origin)
		}
	}
}

// A case-only change to a source key is not a policy change: the effective
// policy is identical, so it must not request a rebuild. Pin the direction —
// the opposite regression (a real change being deduped away) is the bug this
// fixes.
func TestCaseOnlyKeyChangeIsNotTreatedAsAChange(t *testing.T) {
	svc, _ := newPolicyService(t)

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://Example.com/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}
	if !svc.drainAdblockResync() {
		t.Fatal("the first change must request a rebuild")
	}

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://example.com/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}
	if svc.drainAdblockResync() {
		t.Fatal("a case-only change is the same policy and must not request a rebuild")
	}
}

// A real change to the same key must still be published and rebuilt, even when
// only the spelling of the key was touched alongside it.
func TestRealChangeAlongsideAKeyRespellIsPublished(t *testing.T) {
	svc, _ := newPolicyService(t)

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://example.com/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}
	if !svc.drainAdblockResync() {
		t.Fatal("precondition: the first change must request a rebuild")
	}

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://Example.com/hosts":{"category":"ads","scope":"suffix"}}`); err != nil {
		t.Fatal(err)
	}
	if !svc.drainAdblockResync() {
		t.Fatal("a scope change must request a rebuild even when the key is respelled")
	}
	_, scope, _ := svc.adblock.resolveAdblockSourcePolicy("https://example.com/hosts")
	if scope != domaintrie.RuleScopeSuffix {
		t.Fatalf("scope = %v, want suffix", scope)
	}
}

// Parsing must be deterministic. Canonicalizing a map key while ranging over a
// Go map let the winner of a canonical collision depend on map iteration order,
// which is randomized per process: the same document produced different
// policies and different SourcePoliciesFingerprint values on different runs,
// and that fingerprint exists precisely to tell two nodes apart. Measured
// before the fix: 2 distinct fingerprints and a scope flipping between
// "suffix" and "exact" across 400 parses of one document.
func TestParsingADuplicateSourceIsDeterministic(t *testing.T) {
	document := `{
		"https://Example.com/hosts": {"category": "ads", "scope": "exact"},
		"https://example.com/hosts": {"category": "social", "scope": "suffix"}
	}`

	first := adblockSourcePoliciesFingerprint(parseAdblockSourcePolicies(document))
	firstSet := parseAdblockSourcePolicies(document)
	if len(firstSet) != 1 {
		t.Fatalf("a canonical collision must collapse to one entry, got %d: %v", len(firstSet), firstSet)
	}

	for range 2000 {
		set := parseAdblockSourcePolicies(document)
		if got := adblockSourcePoliciesFingerprint(set); got != first {
			t.Fatalf("fingerprint changed between parses: %s != %s", got, first)
		}
		for key, policy := range firstSet {
			if set[key] != policy {
				t.Fatalf("policy for %q changed between parses: %+v != %+v", key, set[key], policy)
			}
		}
	}
}

// The operator save path must refuse a document with a canonical collision
// rather than silently resolving it: which entry wins is an implementation
// detail the operator cannot see, and the two entries say different things
// (here, exact vs suffix, which is the difference between blocking a hostname
// and blocking its subdomains too).
func TestValidateRejectsCanonicallyDuplicateSources(t *testing.T) {
	err := validateAdblockSourcePoliciesJSON(`{
		"https://Example.com/hosts": {"category": "ads", "scope": "exact"},
		"https://example.com/hosts": {"category": "ads", "scope": "suffix"}
	}`)
	if err == nil {
		t.Fatal("expected a canonical collision to be rejected")
	}
	if !strings.Contains(err.Error(), "same source") {
		t.Fatalf("error = %v, want it to explain that the keys are the same source", err)
	}
}

// A single spelling of a source is unaffected by the collision handling.
func TestParseKeepsDistinctSourcesApart(t *testing.T) {
	set := parseAdblockSourcePolicies(`{
		"https://a.test/hosts": {"category": "ads"},
		"https://b.test/hosts": {"category": "tracking"},
		"./local-hosts": {"category": "nuisance"}
	}`)
	if len(set) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(set), set)
	}
}

func newPolicyService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	t.Setenv(envAdblockSourcePoliciesJSON, "")
	t.Setenv(envAdblockEnabled, "false")

	db, err := store.New(filepath.Join(t.TempDir(), "policy.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc, db
}

// The whole point of the feature: a document written here must reach the store
// and be applied, so the other process's 30-second reconcile can pick it up.
// Before this there was no writer at all — the store key was read but never
// written in production, while the docs promised otherwise.
func TestSetAdblockSourcePoliciesJSONPersistsAndApplies(t *testing.T) {
	svc, db := newPolicyService(t)
	ctx := t.Context()

	raw := `{"https://a.test/hosts":{"category":"tracking","scope":"suffix"}}`
	if err := svc.adblock.SetAdblockSourcePoliciesJSON(ctx, svc.store, raw); err != nil {
		t.Fatalf("SetAdblockSourcePoliciesJSON: %v", err)
	}

	stored, err := db.GetSystemConfig(ctx, systemConfigAdblockSourcePolicies)
	if err != nil {
		t.Fatal(err)
	}
	if stored != raw {
		t.Fatalf("stored document = %q, want %q", stored, raw)
	}

	category, scope, origin := svc.adblock.resolveAdblockSourcePolicy("https://a.test/hosts")
	if category != "tracking" || scope != domaintrie.RuleScopeSuffix || origin != domaintrie.OriginSourcePolicySuffix {
		t.Fatalf("policy not applied: category=%q scope=%q origin=%q", category, scope, origin)
	}
}

// A second, already-running process (dns-resolver, or a second core-api)
// reconciles from the store on a timer. That path has to converge on the same
// set, which is what makes the hot reload real.
//
// A process started *after* the write already converges during NewService; the
// interesting case is a long-running peer that was already up.
func TestRefreshConvergesOnAChangeMadeByAnotherProcess(t *testing.T) {
	writer, writerDB := newPolicyService(t)

	reader := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              writerDB,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = reader.Close() })

	emptyFingerprint := adblockSourcePoliciesFingerprint(nil)
	if got := adblockSourcePoliciesFingerprint(reader.adblock.currentAdblockSourcePolicies()); got != emptyFingerprint {
		t.Fatal("precondition: the reader must start with no policy")
	}

	// Another process applies a change.
	if err := writer.adblock.SetAdblockSourcePoliciesJSON(t.Context(), writer.store,
		`{"https://remote.test/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}

	// The running reader reconciles and must agree.
	reader.adblock.refreshAdblockSourcePolicies(reader.store)
	if got := adblockSourcePoliciesFingerprint(reader.adblock.currentAdblockSourcePolicies()); got != adblockSourcePoliciesFingerprint(writer.adblock.currentAdblockSourcePolicies()) {
		t.Fatal("the two processes must agree on the policy fingerprint after a reconcile")
	}
	category, scope, _ := reader.adblock.resolveAdblockSourcePolicy("https://remote.test/hosts")
	if category != "ads" || scope != domaintrie.RuleScopeExact {
		t.Fatalf("reconciled policy not applied: category=%q scope=%q", category, scope)
	}
}

// An empty document clears the override and falls back to the environment.
func TestSetAdblockSourcePoliciesJSONEmptyFallsBackToEnvironment(t *testing.T) {
	svc, db := newPolicyTestServiceWithEnv(t, `{"https://env.test/hosts":{"category":"malware"}}`)
	ctx := t.Context()

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(ctx, svc.store, `{"https://set.test/hosts":{"category":"ads"}}`); err != nil {
		t.Fatal(err)
	}
	if _, ok := svc.adblock.currentAdblockSourcePolicies()[canonicalSourceKey("https://set.test/hosts")]; !ok {
		t.Fatal("precondition: the set policy should be in force")
	}

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(ctx, svc.store, ""); err != nil {
		t.Fatal(err)
	}
	stored, err := db.GetSystemConfig(ctx, systemConfigAdblockSourcePolicies)
	if err != nil {
		t.Fatal(err)
	}
	if stored != "" {
		t.Fatalf("stored document = %q, want empty", stored)
	}
	if _, ok := svc.adblock.currentAdblockSourcePolicies()[canonicalSourceKey("https://env.test/hosts")]; !ok {
		t.Fatal("clearing the override must fall back to the environment policy")
	}
}

func newPolicyTestServiceWithEnv(t *testing.T, envPolicies string) (*Service, *store.DB) {
	t.Helper()
	t.Setenv(envAdblockSourcePoliciesJSON, envPolicies)
	t.Setenv(envAdblockEnabled, "false")

	db, err := store.New(filepath.Join(t.TempDir(), "policy-env.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		AdblockFileRoot:    t.TempDir(),
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	svc.adblock.refreshAdblockSourcePolicies(svc.store)
	return svc, db
}

// The runtime parser repairs a bad document and carries on; an operator save
// must not, or the stored policy silently differs from the intended one.
func TestSetAdblockSourcePoliciesJSONRejectsUnusableDocuments(t *testing.T) {
	svc, db := newPolicyService(t)
	ctx := t.Context()

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"not json", `{nope`, "not a JSON object"},
		{"json array", `["a.test"]`, "not a JSON object"},
		{"json null", `null`, "expected a JSON object"},
		{"unknown category", `{"https://a.test/hosts":{"category":"banana"}}`, "unknown category"},
		{"unknown scope", `{"https://a.test/hosts":{"scope":"sideways"}}`, "unknown scope"},
		{"empty source key", `{"":{"category":"ads"}}`, "source key is empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := svc.adblock.SetAdblockSourcePoliciesJSON(ctx, svc.store, tc.raw)
			if err == nil {
				t.Fatalf("expected %q to be rejected", tc.raw)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tc.want)
			}
			// Nothing may be persisted or applied from a rejected document.
			stored, getErr := db.GetSystemConfig(ctx, systemConfigAdblockSourcePolicies)
			if getErr != nil {
				t.Fatal(getErr)
			}
			if stored != "" {
				t.Fatalf("a rejected document was persisted: %q", stored)
			}
			if len(svc.adblock.currentAdblockSourcePolicies()) != 0 {
				t.Fatal("a rejected document was applied")
			}
		})
	}
}

// A document the runtime accepts must survive the strict validator: the two
// paths must not disagree about what is valid.
func TestStrictValidationAcceptsEveryDocumentTheRuntimeAccepts(t *testing.T) {
	accepted := []string{
		`{}`,
		`{"https://a.test/hosts":{}}`,
		`{"https://a.test/hosts":{"category":"unknown"}}`,
		`{"https://a.test/hosts":{"category":"ads","scope":"exact"}}`,
		`{"https://a.test/hosts":{"category":"tracking","scope":"suffix"}}`,
		`{"https://a.test/hosts":{"category":"ADS","scope":"EXACT"}}`, // case-normalized
		`  {"https://a.test/hosts":{"category":"ads"}}  `,
	}
	for _, raw := range accepted {
		t.Run(raw, func(t *testing.T) {
			if err := validateAdblockSourcePoliciesJSON(raw); err != nil {
				t.Fatalf("the runtime accepts this document but the save path rejects it: %v", err)
			}
		})
	}
}

// The stored document must be what is in force, so the operator UI can
// round-trip it.
func TestAdblockSourcePoliciesJSONRendersTheEffectiveSet(t *testing.T) {
	svc, _ := newPolicyService(t)
	if got := svc.adblock.AdblockSourcePoliciesJSON(); got != "" {
		t.Fatalf("an empty set should render empty, got %q", got)
	}

	if err := svc.adblock.SetAdblockSourcePoliciesJSON(t.Context(), svc.store,
		`{"https://a.test/hosts":{"category":"ads","scope":"exact"}}`); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]map[string]string
	if err := json.Unmarshal([]byte(svc.adblock.AdblockSourcePoliciesJSON()), &decoded); err != nil {
		t.Fatalf("rendered document is not valid JSON: %v", err)
	}
	if decoded["https://a.test/hosts"]["category"] != "ads" {
		t.Fatalf("rendered document = %v", decoded)
	}
}
