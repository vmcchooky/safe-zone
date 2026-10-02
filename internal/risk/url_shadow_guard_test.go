package risk

import (
	"context"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
)

type urlShadowGuardCase struct {
	ID            string   `json:"id"`
	RequestedURL  string   `json:"requested_url"`
	ExpectedHost  string   `json:"expected_host"`
	RedirectChain []string `json:"redirect_chain"`
	Tier          string   `json:"tier"`
}

type urlShadowGuardFixture struct {
	SchemaVersion int                  `json:"schema_version"`
	Cases         []urlShadowGuardCase `json:"cases"`
}

func newGuardedURLService(t *testing.T, redisCache *cache.Redis) *Service {
	t.Helper()
	classifier, err := analysis.NewURLBundleClassifier(filepath.Join("..", "..", "ml", "models", "url-v1"))
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(Options{
		AnalysisConfig:  config.DefaultAnalysisConfig(),
		Redis:           redisCache,
		RedisTimeout:    100 * time.Millisecond,
		TTLAllowed:      time.Hour,
		TTLSuspicious:   time.Hour,
		TTLBlocked:      time.Hour,
		URLMLClassifier: classifier,
		URLMLMode:       analysis.MLModeShadow,
		URLMLShadow:     URLMLShadowConfig{Percent: 100},
	})
	t.Cleanup(func() { _ = service.Close() })
	return service
}

func loadGuardFixture(t *testing.T) []urlShadowGuardCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "analysis", "testdata", "url_shadow_negatives.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture urlShadowGuardFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	return fixture.Cases
}

// URL-shadow trusted-host guard: path-only promotes on trusted-brand hosts
// are held without host-side evidence; everything else stands. Recall on
// must_promote shapes must stay perfect; residual FP is pinned, not hidden.
func TestURLShadowGuardHoldsTrustedHostPromotes(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	service := newGuardedURLService(t, cache.NewRedis(server.Addr(), "", 0))

	fp, fn, held, watchPromote := 0, 0, 0, 0
	for _, tc := range loadGuardFixture(t) {
		observed := service.AnalyzeWithOptions(context.Background(), tc.ExpectedHost, ClientInfo{}, AnalyzeOptions{
			URLContext: &URLAnalysisContext{RequestedURL: tc.RequestedURL, RedirectChain: tc.RedirectChain},
		})
		if observed.URLML == nil || !observed.URLML.Evaluated {
			t.Fatalf("%s: missing URL shadow evaluation: %+v", tc.ID, observed.URLML)
		}
		switch tc.Tier {
		case "must_not_promote":
			if observed.URLML.WouldPromote {
				fp++
			} else if observed.URLML.Held {
				held++
			}
		case "must_promote":
			if !observed.URLML.WouldPromote || observed.URLML.Held {
				fn++
				t.Logf("%s: MISSED promote (held=%v)", tc.ID, observed.URLML.Held)
			}
		case "watch":
			if observed.URLML.WouldPromote {
				watchPromote++
			}
		default:
			t.Fatalf("%s: unknown tier %q", tc.ID, tc.Tier)
		}
	}
	t.Logf("guarded: false_positives=%d held=%d false_negatives=%d watch_promoted=%d", fp, held, fn, watchPromote)
	if fn != 0 {
		t.Fatalf("guard must not cost recall: %d must_promote missed", fn)
	}
	// Measured residual with the url-v1 bundle: 12 negatives still promote
	// (news/CDN/tenant/reserved shapes on hosts the guard does not treat as
	// trusted brands). Pinned: any regression — or silent model change — turns
	// this red.
	//
	// The ceiling was briefly raised to 14 on 2026-09-29, when the guard was
	// changed to condition the hold on a lure marker in the URL path on the
	// theory that this was the documented rule. It was reverted: the two
	// released cases (neg-009 gstatic.com/maps/preview, neg-022
	// apple.com/support/case-…) are model false positives, so holding them is
	// the guard working, and releasing them traded a real protection for a
	// number that only production-traffic data could justify. The guard is
	// blanket by design; see urlPromoteHoldReason.
	if fp > 12 {
		t.Fatalf("guard regression: %d false positives, ceiling is 12", fp)
	}
}

// The guard is blanket: on a trusted-brand host the model does not get to
// promote on its own say-so. This pins that rule directly, because the guard's
// comment spent a year claiming a path-conditioned rule the code never
// implemented.
//
// The two URLs below are the ones a path-conditioned variant released, and both
// are model false positives on hosts the operator does not control the lure
// for. They must stay held.
func TestTrustedHostPromotesAreHeldRegardlessOfThePath(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	service := newGuardedURLService(t, cache.NewRedis(server.Addr(), "", 0))

	for _, raw := range []string{
		"https://gstatic.com/maps/preview/l6432?z=15&token=Qw7712",
		"https://apple.com/support/case-99182753109/page-12?cid=55",
	} {
		observed := service.AnalyzeWithOptions(context.Background(), hostOf(t, raw), ClientInfo{}, AnalyzeOptions{
			URLContext: &URLAnalysisContext{RequestedURL: raw},
		})
		if observed.URLML == nil || !observed.URLML.Evaluated {
			t.Fatalf("%s: missing URL shadow evaluation: %+v", raw, observed.URLML)
		}
		if !observed.URLML.Held {
			t.Fatalf("%s: a promote on a trusted-brand host must be held even when the path looks benign: %+v", raw, observed.URLML)
		}
	}
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host == "" {
		t.Fatalf("no host in %q", raw)
	}
	return parsed.Host
}

// Scoped evidence wins at URL layer too (PR-59 principle): a live exact
// feed IOC on a trusted host overrides the hold.
func TestURLShadowGuardYieldsToExactFeedIOC(t *testing.T) {
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	redisCache := cache.NewRedis(server.Addr(), "", 0)
	service := newGuardedURLService(t, redisCache)

	domain := "evil.sharepoint.com"
	if _, err := redisCache.ZAdd(context.Background(), defaultThreatFeedKey, redis.Z{
		Score:  float64(time.Now().Add(time.Hour).Unix()),
		Member: domain,
	}); err != nil {
		t.Fatal(err)
	}
	observed := service.AnalyzeWithOptions(context.Background(), domain, ClientInfo{}, AnalyzeOptions{
		URLContext: &URLAnalysisContext{RequestedURL: "https://" + domain + "/login/verify?token=abc991"},
	})
	if observed.URLML == nil || !observed.URLML.Evaluated {
		t.Fatalf("missing URL shadow evaluation: %+v", observed.URLML)
	}
	if !observed.URLML.WouldPromote || observed.URLML.Held {
		t.Fatalf("exact feed IOC must override the hold: %+v", observed.URLML)
	}
}

// A blind guard must not suppress: feed lookup errors fail open.
func TestURLShadowGuardFailOpenWithoutRedis(t *testing.T) {
	service := newGuardedURLService(t, nil)
	observed := service.AnalyzeWithOptions(context.Background(), "microsoft.com", ClientInfo{}, AnalyzeOptions{
		URLContext: &URLAnalysisContext{RequestedURL: "https://microsoft.com/account/verify?token=AbC1234567890"},
	})
	if observed.URLML == nil || !observed.URLML.Evaluated {
		t.Fatalf("missing URL shadow evaluation: %+v", observed.URLML)
	}
	if !observed.URLML.WouldPromote || observed.URLML.Held {
		t.Fatalf("lookup error must fail open to promote: %+v", observed.URLML)
	}
}
