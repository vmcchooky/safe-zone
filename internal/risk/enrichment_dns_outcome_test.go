package risk

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"safe-zone/internal/analysis"
	"safe-zone/internal/cache"
	"safe-zone/internal/config"
	"safe-zone/internal/tlsinspect"
	"safe-zone/internal/whois"
)

// TestDNSOutcomeNeverPromotesSecurityScore reproduces H1 across the full
// error-injection matrix: no DNS outcome may change the score or promote
// the verdict on its own. DNS metadata is availability evidence, never
// malice evidence.
func TestDNSOutcomeNeverPromotesSecurityScore(t *testing.T) {
	bases := map[string]analysis.Result{
		"safe25": {
			Domain: "mp-others-sg-sg7-19.dr-wan.shopeemobile.com", Verdict: analysis.VerdictSafe,
			Confidence: 0.6583, Score: 25,
			Reasons:  []string{"domain is long", "many hyphens"},
			Category: "uncategorized",
		},
		"suspicious55": {
			Domain: "zshopeevod.v.baishan-cloud.net", Verdict: analysis.VerdictSuspicious,
			Confidence: 0.9083, Score: 55,
			Reasons:  []string{"domain is long", "suspicious brand subdomain usage (shopee)"},
			Category: "suspicious",
		},
	}
	outcomes := map[string]DNSOutcome{
		"ok":            DNSOutcomeOK,
		"nxdomain":      DNSOutcomeNXDOMAIN,
		"nodata":        DNSOutcomeNoData,
		"timeout":       DNSOutcomeTimeout,
		"serverfailure": DNSOutcomeServerFailure,
		"canceled":      DNSOutcomeCanceled,
		"unknown":       DNSOutcomeUnknownError,
	}
	mixes := map[string]struct {
		tls   tlsinspect.Result
		whois whois.Result
	}{
		"dns_only": {},
		"tls20_whois15": {
			tls:   tlsinspect.Result{Score: 20, Reasons: []string{"tls: test signal"}},
			whois: whois.Result{Score: 15, Reasons: []string{"whois: test signal"}},
		},
		"tls30_only": {
			tls: tlsinspect.Result{Score: 30, Reasons: []string{"tls: certificate name does not match domain"}},
		},
	}

	for baseName, base := range bases {
		for outcomeName, outcome := range outcomes {
			for mixName, mix := range mixes {
				t.Run(baseName+"/"+outcomeName+"/"+mixName, func(t *testing.T) {
					result := base
					result.Reasons = append([]string(nil), base.Reasons...)
					applyEnrichmentSignals(&result, enrichmentSignals{
						DNS: outcome, TLS: mix.tls, WHOIS: mix.whois,
					})
					wantScore := base.Score + mix.tls.Score + mix.whois.Score
					if wantScore > 100 {
						wantScore = 100
					}
					if result.Score != wantScore {
						t.Fatalf("DNS outcome %s changed score %d -> %d (want %d) without security evidence",
							outcomeName, base.Score, result.Score, wantScore)
					}
					// A DNS-only outcome must never promote the verdict.
					if mix.tls.Score+mix.whois.Score == 0 && result.Verdict != base.Verdict {
						t.Fatalf("DNS outcome %s promoted verdict %s -> %s",
							outcomeName, base.Verdict, result.Verdict)
					}
					for _, r := range result.Reasons {
						if r == "domain is not registered or resolving (NXDOMAIN)" {
							t.Fatalf("legacy false NXDOMAIN reason survived for outcome %s", outcomeName)
						}
					}
					if outcome == DNSOutcomeOK {
						if len(result.Reasons) != len(base.Reasons)+len(mix.tls.Reasons)+len(mix.whois.Reasons) {
							t.Fatalf("OK outcome must not add availability notes, got %v", result.Reasons)
						}
					} else if len(result.Reasons) != len(base.Reasons)+len(mix.tls.Reasons)+len(mix.whois.Reasons)+1 {
						t.Fatalf("non-OK outcome must add exactly one availability note, got %v", result.Reasons)
					}
				})
			}
		}
	}
}

// TestClassifyDNSLookupErr pins the error-to-outcome mapping, including the
// authoritative-NXDOMAIN vs timeout distinction that the legacy boolean
// collapsed into a single malicious floor.
func TestClassifyDNSLookupErr(t *testing.T) {
	cases := map[string]struct {
		err  error
		want DNSOutcome
	}{
		"nil":             {nil, DNSOutcomeOK},
		"canceled":        {context.Canceled, DNSOutcomeCanceled},
		"deadline":        {context.DeadlineExceeded, DNSOutcomeTimeout},
		"authoritative":   {&net.DNSError{Err: "no such host", IsNotFound: true}, DNSOutcomeNXDOMAIN},
		"timeout":         {&net.DNSError{Err: "i/o timeout", IsTimeout: true}, DNSOutcomeTimeout},
		"servfail":        {&net.DNSError{Err: "server misbehaving", Server: "192.0.2.1"}, DNSOutcomeServerFailure},
		"refused":         {&net.DNSError{Err: "query refused"}, DNSOutcomeServerFailure},
		"generic":         {errors.New("boom"), DNSOutcomeUnknownError},
		"wrapped_timeout": {&net.DNSError{Err: "i/o timeout", IsTimeout: true}, DNSOutcomeTimeout},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := classifyDNSLookupErr(tc.err); got != tc.want {
				t.Fatalf("classifyDNSLookupErr(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestEnrichmentTimeoutOutcomePreservesCachedVerdict is the end-to-end leg:
// a worker job that observes only a DNS timeout must write back the
// unchanged evaluation instead of a floored MALICIOUS.
func TestEnrichmentTimeoutOutcomePreservesCachedVerdict(t *testing.T) {
	t.Setenv("SAFE_ZONE_ADBLOCK_ENABLED", "false")
	server, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	svc := NewService(Options{
		AnalysisConfig: config.DefaultAnalysisConfig(),
		Redis:          cache.NewRedis(server.Addr(), "", 0),
		RedisTimeout:   time.Second,
	})
	defer func() { _ = svc.Close() }()

	domain := "zshopeevod.v.baishan-cloud.net"
	lexical := svc.analyzeLexical(domain)
	if lexical.Verdict != analysis.VerdictSuspicious || lexical.Score != 55 {
		t.Fatalf("fixture lexical changed: %+v", lexical)
	}
	svc.enrichmentLookup = func(context.Context, string) enrichmentSignals {
		return enrichmentSignals{DNS: DNSOutcomeTimeout}
	}
	job := enrichmentJob{
		Domain:         domain,
		Result:         lexical,
		ConfigRevision: svc.currentConfigRevision(),
	}
	svc.processEnrichmentJob(job)

	key := analysisCacheKey(domain, svc.currentMLPolicyRevision())
	var after analysisCacheEntry
	found, err := svc.redis.GetJSON(context.Background(), key, &after)
	if err != nil || !found {
		t.Fatalf("expected worker cache write, found=%v err=%v", found, err)
	}
	if after.Result.Verdict != analysis.VerdictSuspicious || after.Result.Score != 55 {
		t.Fatalf("timeout outcome rewrote evaluation: %+v", after.Result)
	}
	if after.EnrichedAt == "" {
		t.Fatal("expected EnrichedAt marker on worker write")
	}
}
