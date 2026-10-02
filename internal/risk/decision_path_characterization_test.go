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

func decisionScenarios(t *testing.T, ctx context.Context) []decisionScenario {
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
				svc.AdblockTrieOverride(trie)
			},
			wantAction: "block",
		},
		{
			name: "override beats adblock",
			dom:  "ads.winned.example",
			build: func(t *testing.T, ctx context.Context, svc *Service, db *store.DB) {
				trie := domaintrie.NewTrie()
				trie.Add("winned.example")
				svc.AdblockTrieOverride(trie)
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
				svc.AdblockTrieOverride(trie)
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

	for _, sc := range decisionScenarios(t, ctx) {
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

	for _, sc := range decisionScenarios(t, ctx) {
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

// TestPolicyDecisionIsPopulatedAsymmetrically pins the one place the two paths
// are known to disagree, because it is invisible to every existing check and it
// constrains the refactor in a way that is easy to trip over.
//
// Measured current behaviour:
//
//	an administrative override or a whitelist match populates Decision on
//	Analyze and leaves it nil on Policy;
//	an adblock match populates Decision on Policy and leaves it nil on Analyze;
//	a domain that fails normalisation populates neither.
//
// Policy's own field comment acknowledges the first half: "Nil on paths that have
// not adopted the separated decision model yet."
//
// Why this matters more than it looks. internal/eval/runner.go Observe() reduces
// an observation by reading Decision from Policy only:
//
//	decision := ""
//	if pol.Decision != nil {
//	    decision = pol.Decision.Action + "|" + pol.Decision.Kind + "|" + pol.Decision.Category
//	}
//
// So every admin-override and whitelist decision is recorded in the frozen
// decision corpora as the empty string. That is the contract the `eval:decision`
// gate checks against, and it currently passes.
//
// Unifying the paths in the obvious way — letting Policy populate Decision for
// administrative decisions too — changes what Observe records. The corpora would
// have to be regenerated to match, and regenerating them is how a gate quietly
// stops meaning anything.
//
// A refactor must therefore choose deliberately: preserve the asymmetry, or adopt
// the decision model on Policy and re-baseline the corpora as a separate, visible
// step. Doing it as a side effect of a "pure" deduplication would be the worst of
// both.
func TestPolicyDecisionIsPopulatedAsymmetrically(t *testing.T) {
	ctx := context.Background()

	for _, sc := range decisionScenarios(t, ctx) {
		t.Run(sc.name, func(t *testing.T) {
			svc, db := newDecisionPathService(t)
			if sc.build != nil {
				sc.build(t, ctx, svc, db)
			}

			api := svc.Analyze(ctx, sc.dom, ClientInfo{})
			pol := svc.Policy(ctx, sc.dom, ClientInfo{})

			switch {
			case api.Decision != nil && api.Decision.Kind != "content":
				// Administrative or allowlist admission: Analyze explains it,
				// Policy does not.
				if pol.Decision != nil {
					t.Fatalf("Policy.Decision is now populated with kind %q for %q; "+
						"internal/eval/runner.go reads Decision from Policy only, so the "+
						"frozen corpora's recorded decision string changes and "+
						"`eval:decision` must be re-baselined deliberately",
						pol.Decision.Kind, sc.dom)
				}
			case pol.Decision != nil && pol.Decision.Kind == "content":
				// Adblock content policy: Policy explains it, Analyze does not.
				if api.Decision != nil {
					t.Fatalf("Analyze.Decision is now populated with kind %q for %q; "+
						"this path never carried content decisions",
						api.Decision.Kind, sc.dom)
				}
			}
		})
	}
}
