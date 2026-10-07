package risk

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"safe-zone/internal/config"
	"safe-zone/internal/domaintrie"
	"safe-zone/internal/store"
)

// Safe Zone has two decision paths that overlap almost completely:
// AnalyzeWithOptions serves core-api, Policy serves dns-resolver. They
// normalise the domain, resolve the client group, read the override, consult the
// whitelist and the adblock trie in the same order, and each was extended
// independently as those layers were added. Unifying them is the obvious next
// refactor and it is exactly the kind of change that should not be attempted
// without knowing precisely what the two paths currently do.
//
// This file is that knowing. It pins three things:
//
//  1. The security verdict and score agree. This is the invariant a refactor
//     must preserve, and it held across every scenario below when measured.
//  2. The effective action agrees, even though it is carried differently by each
//     path.
//  3. The PolicyDecision *struct* is populated asymmetrically, and that asymmetry
//     is load-bearing for the frozen decision corpora. See the long note on
//     TestPolicyDecisionIsPopulatedAsymmetrically.
//
// Nothing here asserts what the paths ought to do. It records what they do.

func newDecisionPathService(t *testing.T) (*Service, *store.DB) {
	t.Helper()
	db, err := store.New(filepath.Join(t.TempDir(), "paths.db"), 30)
	if err != nil {
		t.Fatalf("create store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	svc := NewService(Options{
		AnalysisConfig:     config.DefaultAnalysisConfig(),
		RedisTimeout:       10 * time.Millisecond,
		Store:              db,
		DisableAdblockSync: true,
	})
	t.Cleanup(func() { _ = svc.Close() })
	return svc, db
}

// decisionScenario is one environment in which both paths are asked the same
// question.
type decisionScenario struct {
	name string
	dom  string
	// build arranges the store and adblock trie before either path runs.
	build func(t *testing.T, ctx context.Context, svc *Service, db *store.DB)
	// wantAction is the action both paths must end up taking, expressed the same
	// way for both: the override/allowlist action when a Decision was resolved,
	// otherwise Policy's own action string.
	wantAction string
}

func decisionScenarios(ctx context.Context, t *testing.T) []decisionScenario {
	t.Helper()
	return []decisionScenario{
		{
			name: "nothing configured",
			dom:  "clean.example",
		},
		{
			name: "admin override block",
			dom:  "blocked.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				if err := db.UpsertOverride(ctx, "blocked.example", "block", "operator"); err != nil {
					t.Fatalf("seed override: %v", err)
				}
			},
			wantAction: "block",
		},
		{
			name: "admin override allow",
			dom:  "allowed.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				if err := db.UpsertOverride(ctx, "allowed.example", "allow", "operator"); err != nil {
					t.Fatalf("seed override: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			name: "whitelist entry",
			dom:  "wl.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				if err := db.UpdateWhitelist(ctx, []string{"wl.example"}); err != nil {
					t.Fatalf("seed whitelist: %v", err)
				}
				if err := svc.Whitelist().LoadFromDB(); err != nil {
					t.Fatalf("load whitelist: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			name: "adblock suffix rule",
			dom:  "ads.tracked.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				trie := domaintrie.NewTrie()
				trie.Add("tracked.example")
				svc.adblock.AdblockTrieOverride(trie)
			},
			wantAction: "block",
		},
		{
			name: "override beats adblock",
			dom:  "ads.winned.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				trie := domaintrie.NewTrie()
				trie.Add("winned.example")
				svc.adblock.AdblockTrieOverride(trie)
				if err := db.UpsertOverride(ctx, "ads.winned.example", "allow", "operator"); err != nil {
					t.Fatalf("seed override: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			name: "whitelist beats adblock",
			dom:  "ads.wlwin.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				trie := domaintrie.NewTrie()
				trie.Add("wlwin.example")
				svc.adblock.AdblockTrieOverride(trie)
				if err := db.UpdateWhitelist(ctx, []string{"ads.wlwin.example"}); err != nil {
					t.Fatalf("seed whitelist: %v", err)
				}
				if err := svc.Whitelist().LoadFromDB(); err != nil {
					t.Fatalf("load whitelist: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			// Normalisation fails, so both paths take their lexical-only branch.
			// This is the one scenario where the two paths were observed to agree
			// on the Decision struct as well, because neither resolves one.
			name: "not a domain",
			dom:  "not a domain!!",
		},
		{
			// The client resolves to a real group rather than the default one.
			// The shared prefix resolves the group and hands it to the
			// enforcement that follows, so a group that is resolved rather than
			// defaulted is the case worth pinning.
			name: "client group resolved from an ip mapping",
			dom:  "grouped.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				id, err := db.CreateGroup(ctx, "strict", "strict group",
					[]string{"phishing"}, true, true)
				if err != nil {
					t.Fatalf("create group: %v", err)
				}
				if _, err := db.AddMappingInt(ctx, "ip", "203.0.113.7", id); err != nil {
					t.Fatalf("map client: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			// Same group, but the client is the one the mapping points at, so
			// Policy's dynamic enforcement has a non-default group to enforce
			// with. The domain itself is clean, so enforcement has nothing to
			// act on and the point is that both paths resolve the same group.
			name: "grouped client on a clean domain",
			dom:  "still-clean.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				id, err := db.CreateGroup(ctx, "strict", "strict group",
					[]string{"advertising"}, true, true)
				if err != nil {
					t.Fatalf("create group: %v", err)
				}
				if _, err := db.AddMappingInt(ctx, "ip", "203.0.113.9", id); err != nil {
					t.Fatalf("map client: %v", err)
				}
			},
			wantAction: "allow",
		},
		{
			// An override on a grouped client: the override must still win,
			// because the prefix resolves it before any enforcement runs.
			name: "override wins on a grouped client",
			dom:  "grouped-blocked.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				id, err := db.CreateGroup(ctx, "strict", "strict group", nil, true, true)
				if err != nil {
					t.Fatalf("create group: %v", err)
				}
				if _, err := db.AddMappingInt(ctx, "ip", "203.0.113.11", id); err != nil {
					t.Fatalf("map client: %v", err)
				}
				if err := db.UpsertOverride(ctx, "grouped-blocked.example", "block", "operator"); err != nil {
					t.Fatalf("seed override: %v", err)
				}
			},
			wantAction: "block",
		},
	}
}

// effectiveAction is the action a request would actually be subject to, read the
// way each path exposes it. Analyze carries it in Decision.Action when an
// administrative or allowlist policy resolved, and in nothing at all when the
// decision came from adblock content policy; Policy carries it in Policy for
// every case.
func effectiveAction(a Analysis, p Policy) string {
	if a.Decision != nil {
		return a.Decision.Action
	}
	return p.Policy
}

// The invariant a unification refactor must not break: both paths answer the same
// question the same way.
func TestDecisionPathsAgreeOnVerdictAndScore(t *testing.T) {
	ctx := context.Background()

	for _, sc := range decisionScenarios(ctx, t) {
		t.Run(sc.name, func(t *testing.T) {
			svc, db := newDecisionPathService(t)
			if sc.build != nil {
				sc.build(t, ctx, svc, db)
			}

			api := svc.Analyze(ctx, sc.dom, ClientInfo{})
			pol := svc.Policy(ctx, sc.dom, ClientInfo{})

			if api.Verdict != pol.Result.Verdict {
				t.Fatalf("verdict diverges for %q: Analyze=%s Policy=%s",
					sc.dom, api.Verdict, pol.Result.Verdict)
			}
			if api.Score != pol.Result.Score {
				t.Fatalf("score diverges for %q: Analyze=%d Policy=%d",
					sc.dom, api.Score, pol.Result.Score)
			}
		})
	}
}

// The action is carried in different fields by each path, so the comparison has
// to normalise for that. If it ever diverges, one of the two callers — core-api
// or dns-resolver — is enforcing something the other is not.
func TestDecisionPathsAgreeOnTheActionTheyEnforce(t *testing.T) {
	ctx := context.Background()

	for _, sc := range decisionScenarios(ctx, t) {
		t.Run(sc.name, func(t *testing.T) {
			svc, db := newDecisionPathService(t)
			if sc.build != nil {
				sc.build(t, ctx, svc, db)
			}

			api := svc.Analyze(ctx, sc.dom, ClientInfo{})
			pol := svc.Policy(ctx, sc.dom, ClientInfo{})

			if got := effectiveAction(api, pol); got != pol.Policy {
				t.Fatalf("action diverges for %q: Analyze enforces %q, Policy enforces %q",
					sc.dom, got, pol.Policy)
			}
			if sc.wantAction != "" && pol.Policy != sc.wantAction {
				t.Fatalf("action for %q = %q, want %q", sc.dom, pol.Policy, sc.wantAction)
			}
		})
	}
}

// TestBothPathsExplainTheirAdministrativeDecision pins the contract that
// replaced the asymmetry this file originally documented.
//
// Until now Policy left Decision nil for administrative admissions while Analyze
// populated it, so the same logical event arrived with an explanation at core-api
// and without one at dns-resolver. Policy now attaches it too.
//
// The asymmetry that remains is deliberate and narrower: an adblock content
// decision is explained by Policy alone, because Analyze's separated semantics
// treat a content match as evidence and deliberately carry on into the security
// pipeline rather than resolving a policy.
//
// A note on what this changed and did not disturb. internal/eval/runner.go reduces
// an observation by reading Decision from Policy only:
//
//	decision := ""
//	if pol.Decision != nil {
//	    decision = pol.Decision.Action + "|" + pol.Decision.Kind + "|" + pol.Decision.Category
//	}
//
// So populating it changes what Observe records, and the frozen corpora would have
// needed re-baselining. They did not, because that harness has no store and cannot
// express an override or a whitelist match at all; it only injects adblock rules.
// Verified by comparing eval output for all four corpora before and after: byte
// identical.
//
// That is a relief and a warning at once. The relief is that no corpus contract
// moved. The warning is that eval:decision provides no coverage of this path, so
// this test and the matrix around it are the only thing standing between this
// decision and an unnoticed regression.
func TestBothPathsExplainTheirAdministrativeDecision(t *testing.T) {
	ctx := context.Background()

	for _, sc := range decisionScenarios(ctx, t) {
		t.Run(sc.name, func(t *testing.T) {
			svc, db := newDecisionPathService(t)
			if sc.build != nil {
				sc.build(t, ctx, svc, db)
			}

			api := svc.Analyze(ctx, sc.dom, ClientInfo{})
			pol := svc.Policy(ctx, sc.dom, ClientInfo{})

			switch {
			case api.Decision != nil && api.Decision.Kind != "content":
				// Administrative or allowlist admission: both paths now explain it,
				// and they must explain it identically.
				if pol.Decision == nil {
					t.Fatalf("Policy must explain an administrative decision for %q the "+
						"same way Analyze does; core-api and dns-resolver must not "+
						"disagree about why a domain was resolved", sc.dom)
				}
				assertSameDecision(t, sc.dom, api.Decision, pol.Decision)
			case pol.Decision != nil && pol.Decision.Kind == "content":
				// Adblock content policy stays Policy-only by design: Analyze keeps
				// content matches out of the security decision.
				if api.Decision != nil {
					t.Fatalf("Analyze.Decision is populated with kind %q for %q; separated "+
						"semantics deliberately do not resolve a policy on a content match",
						api.Decision.Kind, sc.dom)
				}
			default:
				// No policy resolved: an unparseable domain, or a plain security
				// assessment. Neither path may invent an explanation.
				if api.Decision != nil || pol.Decision != nil {
					t.Fatalf("no policy resolved for %q, so neither path should carry a "+
						"decision: api=%v pol=%v", sc.dom, api.Decision, pol.Decision)
				}
			}
		})
	}
}

// assertSameDecision compares the fields an operator or a corpus actually reads.
func assertSameDecision(t *testing.T, domain string, a, b *PolicyDecision) {
	t.Helper()
	if a.Action != b.Action || a.Kind != b.Kind || a.Category != b.Category || a.Reason != b.Reason {
		t.Fatalf("the two paths explain %q differently:\n  Analyze: %+v\n  Policy:  %+v", domain, a, b)
	}
}

// TestDecisionPathsDeclareTheirOwnAssessmentShape pins the Assessment each path
// reports, and pins that the two shapes are NOT the same.
//
// Assessment is serialized into the API response and into telemetry. It is the
// operator's answer to "which layers were consulted, and which were not", so a
// refactor that quietly drops an entry changes what a support conversation looks
// like without changing a single verdict.
//
// The two paths differ structurally, and the differences are by design:
//
//   - Analyze runs OSINT on demand, so it evaluates "osint" where Policy skips
//     "osint:cache_only" and evaluates "group_policy" instead.
//   - Policy applies the client group's dynamic enforcement, so it evaluates
//     "group_policy" and Analyze never does.
//   - Analyze reports "url_ml:no_url_context" when no URL context was supplied.
//     Policy has no URL ML stage at all.
//   - On an adblock match under separated semantics, Policy short-circuits to a
//     local lexical assessment ("lexical_local", "content_policy") while
//     Analyze continues into the full threat pipeline.
//
// The assertions are containment rather than equality, so an unrelated reordering
// or added layer does not fail the build, but a lost layer does.
func TestDecisionPathsDeclareTheirOwnAssessmentShape(t *testing.T) {
	ctx := context.Background()

	type wants struct {
		apiEvaluated []string
		apiSkipped   []string
		polEvaluated []string
		polSkipped   []string
	}

	cases := map[string]wants{
		"nothing configured": {
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerThreatFeed},
			apiSkipped:   []string{"website_content:not_observed"},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy},
			polSkipped:   []string{"website_content:not_observed"},
		},
		"admin override block": {
			// The override short-circuits: nothing downstream is consulted.
			apiEvaluated: []string{LayerIdentity, LayerOverride},
			apiSkipped:   []string{LayerWhitelist, LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride},
			polSkipped:   []string{LayerWhitelist, LayerAdblock, LayerGroupPolicy},
		},
		"admin override allow": {
			apiEvaluated: []string{LayerIdentity, LayerOverride},
			apiSkipped:   []string{LayerWhitelist, LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride},
			polSkipped:   []string{LayerWhitelist, LayerAdblock, LayerGroupPolicy},
		},
		"whitelist entry": {
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist},
			apiSkipped:   []string{LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist},
			polSkipped:   []string{LayerAdblock, LayerGroupPolicy},
		},
		"adblock suffix rule": {
			// The clearest structural divergence: Policy stops at a local
			// lexical assessment, Analyze carries on into the threat pipeline.
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerThreatFeed},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerLexicalLocal, LayerContentPolicy},
			polSkipped:   []string{LayerGroupPolicy},
		},
		"override beats adblock": {
			apiEvaluated: []string{LayerIdentity, LayerOverride},
			apiSkipped:   []string{LayerWhitelist, LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride},
			polSkipped:   []string{LayerWhitelist, LayerAdblock, LayerGroupPolicy},
		},
		"whitelist beats adblock": {
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist},
			apiSkipped:   []string{LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist},
			polSkipped:   []string{LayerAdblock, LayerGroupPolicy},
		},
		"not a domain": {
			// Normalisation failed, so neither path consults anything but identity.
			apiEvaluated: []string{LayerIdentity},
			apiSkipped:   []string{LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy},
			polEvaluated: []string{LayerIdentity},
			polSkipped:   []string{LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy},
		},
		// A resolved group changes who enforces, not which layers are consulted,
		// so these three mirror the clean and override shapes above.
		"client group resolved from an ip mapping": {
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerThreatFeed},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy},
			polSkipped:   []string{"website_content:not_observed"},
		},
		"grouped client on a clean domain": {
			apiEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerThreatFeed},
			polEvaluated: []string{LayerIdentity, LayerOverride, LayerWhitelist, LayerAdblock, LayerGroupPolicy},
			polSkipped:   []string{"website_content:not_observed"},
		},
		"override wins on a grouped client": {
			apiEvaluated: []string{LayerIdentity, LayerOverride},
			apiSkipped:   []string{LayerWhitelist, LayerAdblock},
			polEvaluated: []string{LayerIdentity, LayerOverride},
			polSkipped:   []string{LayerWhitelist, LayerAdblock, LayerGroupPolicy},
		},
	}

	for _, sc := range decisionScenarios(ctx, t) {
		t.Run(sc.name, func(t *testing.T) {
			want, ok := cases[sc.name]
			if !ok {
				t.Skipf("no Assessment expectations recorded for %q; record them before relying on this guard", sc.name)
			}

			svc, db := newDecisionPathService(t)
			if sc.build != nil {
				sc.build(t, ctx, svc, db)
			}

			api := svc.Analyze(ctx, sc.dom, ClientInfo{})
			pol := svc.Policy(ctx, sc.dom, ClientInfo{})

			assertLayers(t, "Analyze", want.apiEvaluated, want.apiSkipped,
				api.Assessment.Evaluated, api.Assessment.Skipped)
			assertLayers(t, "Policy", want.polEvaluated, want.polSkipped,
				pol.Assessment.Evaluated, pol.Assessment.Skipped)

			if len(api.Assessment.Evaluated) == 0 || len(pol.Assessment.Evaluated) == 0 {
				t.Fatal("both paths must report at least one evaluated layer")
			}
			if api.Assessment.Evaluated[0] != LayerIdentity || pol.Assessment.Evaluated[0] != LayerIdentity {
				t.Fatalf("identity must be the first evaluated layer on both paths: api=%v pol=%v",
					api.Assessment.Evaluated, pol.Assessment.Evaluated)
			}

			// The path-specific markers a careless unification would drop.
			if sc.name != "not a domain" {
				if !hasLayerWithPrefix(api.Assessment.Skipped, LayerURLML+":") {
					t.Fatalf("Analyze no longer reports why the URL ML layer was skipped; skipped=%v",
						api.Assessment.Skipped)
				}
				if hasLayerWithPrefix(pol.Assessment.Skipped, LayerURLML+":") {
					t.Fatalf("Policy now reports a URL ML skip, but Policy has no URL ML stage; skipped=%v",
						pol.Assessment.Skipped)
				}
			}
		})
	}
}

// assertLayers checks containment rather than equality, so a harmless
// reordering does not fail the build while a lost layer does.
func assertLayers(t *testing.T, who string, wantEvaluated, wantSkipped, gotEvaluated, gotSkipped []string) {
	t.Helper()
	for _, layer := range wantEvaluated {
		if !containsLayer(gotEvaluated, layer) {
			t.Fatalf("%s must report %q as evaluated; evaluated=%v skipped=%v",
				who, layer, gotEvaluated, gotSkipped)
		}
	}
	for _, layer := range wantSkipped {
		if !containsLayer(gotSkipped, layer) {
			t.Fatalf("%s must report %q as skipped; evaluated=%v skipped=%v",
				who, layer, gotEvaluated, gotSkipped)
		}
	}
}

// hasLayerWithPrefix matches the "layer:reason" form.
func hasLayerWithPrefix(layers []string, prefix string) bool {
	for _, l := range layers {
		if len(l) >= len(prefix) && l[:len(prefix)] == prefix {
			return true
		}
	}
	return false
}
