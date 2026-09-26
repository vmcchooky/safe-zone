package main

import "testing"

func TestClassifyDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		reasons []string
		want    Class
	}{
		{
			name:   "operator override wins over every hint",
			domain: "someshop.example",
			reasons: []string{
				`["admin override: block (Manual override from dashboard)"]`,
			},
			want: ClassOperatorOverride,
		},
		{
			name:   "shared serving host is checked before hint lists",
			domain: "cdn.jsdelivr.net",
			// "cdn" would otherwise look like advertising infrastructure and
			// the host is shared infrastructure whose blocking cascades.
			reasons: []string{`[]`},
			want:    ClassSharedInfra,
		},
		{
			name:    "self-service hosting root is shared infra",
			domain:  "pages.dev",
			reasons: []string{`[]`},
			want:    ClassSharedInfra,
		},
		{
			name:    "messaging endpoint is a critical service",
			domain:  "log.api.zaloapp.com",
			reasons: []string{`[]`},
			want:    ClassCriticalService,
		},
		{
			name:    "payment endpoint is a critical service",
			domain:  "api.shopeepay.vn",
			reasons: []string{`[]`},
			want:    ClassCriticalService,
		},
		{
			name:    "crash reporting is app critical",
			domain:  "firebase-settings.crashlytics.com",
			reasons: []string{`["domain is long"]`},
			want:    ClassAppCritical,
		},
		{
			name:    "advertising endpoint is intended suppression",
			domain:  "googleads.g.doubleclick.net",
			reasons: []string{`[]`},
			want:    ClassAdsTracking,
		},
		{
			name:    "unrecognised domain needs review",
			domain:  "some-unknown-endpoint.example",
			reasons: []string{`[]`},
			want:    ClassUnclassified,
		},
		{
			name:    "empty domain is not classifiable",
			domain:  "   ",
			reasons: nil,
			want:    ClassUnclassified,
		},
		{
			// Regression: a whole-host substring test matched "card" inside
			// "scorecardresearch" and mislabelled an ad-research domain as a
			// payment endpoint. Substring hints must stay unambiguous.
			name:    "card inside scorecardresearch is not a payment hint",
			domain:  "census-app.scorecardresearch.com",
			reasons: []string{`[]`},
			want:    ClassAdsTracking,
		},
		{
			// Regression: "otp" matched the middle of a random subdomain token.
			// An exact hint must only fire on a real label named "otp".
			//
			// The expected class is app_critical rather than ads_tracking
			// because the same host also contains "cdn-settings", and class
			// order ranks application infrastructure above advertising. The
			// point of this case is that the short "otp" token is no longer
			// what classifies it.
			name:    "otp inside a random token is not an otp hint",
			domain:  "otpi00g.cdn-settings.appsflyersdk.com",
			reasons: []string{`[]`},
			want:    ClassAppCritical,
		},
		{
			// Regression guard: the same short tokens must still work when they
			// really are the label, otherwise the fix above would silently
			// stop detecting the infrastructure it was meant to catch.
			name:    "a real gov label is still critical",
			domain:  "f-emcc.ngsp.gov.vn",
			reasons: []string{`[]`},
			want:    ClassCriticalService,
		},
		{
			name:    "a real otp label is still critical",
			domain:  "api.otp.bank.example",
			reasons: []string{`[]`},
			want:    ClassCriticalService,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyDomain(tc.domain, tc.reasons); got != tc.want {
				t.Fatalf("classifyDomain(%q) = %q; want %q", tc.domain, got, tc.want)
			}
		})
	}
}

func TestClassSeverityOrdersDamage(t *testing.T) {
	// A wrong block on a payment endpoint is an outage; a wrong block on an
	// advertising endpoint is a non-event. The ordering must reflect that.
	order := []Class{
		ClassCriticalService,
		ClassAppCritical,
		ClassSharedInfra,
		ClassOperatorOverride,
		ClassUnclassified,
		ClassAdsTracking,
	}
	for i := 1; i < len(order); i++ {
		if order[i-1].severity() >= order[i].severity() {
			t.Fatalf("severity(%q)=%d must be strictly less than severity(%q)=%d",
				order[i-1], order[i-1].severity(), order[i], order[i].severity())
		}
	}
}

func TestRecommendationNeverSuggestsAutomaticUnblock(t *testing.T) {
	// Every class must route to a human decision or an explicit keep. The
	// tool must never imply that it can release a block by itself.
	for _, class := range []Class{
		ClassOperatorOverride, ClassCriticalService, ClassAppCritical,
		ClassSharedInfra, ClassAdsTracking, ClassUnclassified,
	} {
		action := class.recommendation()
		if action == "" {
			t.Fatalf("class %q has no recommendation", class)
		}
	}
	if got := ClassAdsTracking.recommendation(); got != "keep: intended suppression" {
		t.Fatalf("ads recommendation = %q; want the keep wording", got)
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique(appendUnique(appendUnique(nil, "a"), "b"), "a")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("appendUnique produced %v; want [a b]", got)
	}
	if got := appendUnique([]string{"x"}, ""); len(got) != 1 {
		t.Fatalf("appendUnique must ignore empty values, got %v", got)
	}
}
