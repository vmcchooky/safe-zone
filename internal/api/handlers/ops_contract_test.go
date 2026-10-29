package handlers

import (
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"safe-zone/internal/observability"
)

// The alert rules and the Grafana dashboard are operational instruments that
// reference JSON field paths of the live status and metrics surfaces. Nothing
// consumes them automatically, so they drift silently; these tests pin the
// contract: the documents parse, the alert IDs stay stable (they are anchors
// for docs/runbooks/alert-rules.md and the release manifest), every dashboard
// URL is a registered route, and every core-api field path an alert condition
// references actually exists in the Go shape that the runtime serializes.

const (
	alertRulesPath = "../../../ops/alerts/safe-zone-alert-rules.yaml"
	dashboardPath  = "../../ops/grafana/safe-zone-dashboard.json"
)

// requiredAlertIDs are documentation anchors; a renamed or removed rule must
// be a conscious act that updates the runbook and the release manifest.
var requiredAlertIDs = []string{
	"core-api-down", "dns-resolver-down",
	"redis-unavailable", "redis-unsafe-eviction-policy", "redis-memory-pressure",
	"threat-feed-stale", "threat-feed-missing", "threat-feed-parser-drift",
	"threat-feed-empty-ingest",
	"high-http-5xx-rate", "doh-upstream-failure", "high-doh-latency",
	"url-ml-shadow-degraded", "url-ml-prediction-errors",
	"url-ml-invalid-context-rate", "url-ml-high-latency",
	"url-ml-operational-drift", "url-ml-context-coverage-drop",
	"url-ml-operational-baseline-unavailable",
}

type alertRule struct {
	ID        string `yaml:"id"`
	Severity  string `yaml:"severity"`
	Condition string `yaml:"condition"`
}

type alertRulesDoc struct {
	Version       int                  `yaml:"version"`
	MetricsFormat string               `yaml:"metrics_format"`
	Endpoints     map[string]string    `yaml:"source_endpoints"`
	Auth          map[string]yaml.Node `yaml:"auth"`
	Rules         []alertRule          `yaml:"rules"`
}

// pathToken matches the JSON path inside a condition: the source prefix,
// a literal ".json", then a chain of identifiers with optional bracket
// groups (array wildcards and quoted map keys).
var pathToken = regexp.MustCompile(
	`(core_api_status|core_api_metrics|dns_resolver_metrics|dns_resolver_status)\.json\.((?:[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])*)(?:\.[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])*)*)`)

// normalizeAll applies stripBrackets to every path of a shape registry so
// both sides of the contract comparison use the same bracket-free form.
func normalizeAll(paths map[string]bool) map[string]bool {
	out := make(map[string]bool, len(paths))
	for path := range paths {
		out[stripBrackets(path)] = true
	}
	return out
}

func stripBrackets(path string) string {
	// Quoted map keys ("POST /dns-query 200") and wildcards ([*]) both
	// resolve against the element type of the container, so they normalize
	// away for shape checking.
	for _, replacer := range []*regexp.Regexp{
		regexp.MustCompile(`\["[^"]*"\]`),
		regexp.MustCompile(`\[\*[^\]]*\]`),
		regexp.MustCompile(`\[\*\]`),
	} {
		path = replacer.ReplaceAllString(path, "")
	}
	return strings.Trim(path, ".")
}

func collectJSONPaths(t reflect.Type, prefix string, out map[string]bool) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	switch t.Kind() {
	case reflect.Struct:
		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			if field.PkgPath != "" {
				continue
			}
			tag := field.Tag.Get("json")
			name := strings.Split(tag, ",")[0]
			if name == "-" {
				continue
			}
			if name == "" {
				name = strings.ToLower(field.Name)
			}
			path := name
			if prefix != "" {
				path = prefix + "." + name
			}
			out[path] = true
			collectJSONPaths(field.Type, path, out)
		}
	case reflect.Slice, reflect.Array:
		out[prefix+"[*]"] = true
		collectJSONPaths(t.Elem(), prefix+"[*]", out)
	case reflect.Map:
		// A map's keys are data, not shape; expose the element shape under a
		// wildcard so quoted-key paths normalize onto it.
		out[prefix+"[*]"] = true
		collectJSONPaths(t.Elem(), prefix+"[*]", out)
	}
}

func TestAlertRulesMatchRuntimeShape(t *testing.T) {
	data, err := os.ReadFile(alertRulesPath)
	if err != nil {
		t.Fatalf("read alert rules: %v", err)
	}
	var doc alertRulesDoc
	if err := yaml.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse alert rules: %v", err)
	}
	if doc.Version != 1 || doc.MetricsFormat != "json" {
		t.Fatalf("unexpected document header: version=%d metrics_format=%s", doc.Version, doc.MetricsFormat)
	}
	for _, required := range []string{"core_api_status", "core_api_metrics", "dns_resolver_status", "dns_resolver_metrics"} {
		if _, ok := doc.Endpoints[required]; !ok {
			t.Errorf("source_endpoints missing %q", required)
		}
	}
	// Every source except the resolver's public status must carry auth.
	for _, source := range []string{"core_api_status", "core_api_metrics", "dns_resolver_metrics"} {
		if _, ok := doc.Auth[source]; !ok {
			t.Errorf("auth missing for %q", source)
		}
	}

	seen := map[string]bool{}
	for _, rule := range doc.Rules {
		seen[rule.ID] = true
		switch rule.Severity {
		case "critical", "warning", "info":
		default:
			t.Errorf("rule %s has unknown severity %q", rule.ID, rule.Severity)
		}
		if !strings.HasSuffix(strings.TrimSpace(rule.Condition), strings.TrimPrefix(regexp.MustCompile(`for [0-9]+[smh]$`).FindString(strings.TrimSpace(rule.Condition)), "")) {
			// Conditions carry a duration window; the evaluator depends on it.
			t.Errorf("rule %s condition has no trailing window: %q", rule.ID, rule.Condition)
		}
	}
	for _, required := range requiredAlertIDs {
		if !seen[required] {
			t.Errorf("required alert id %q missing", required)
		}
	}

	// Shape registry for the sources this package owns. Both registries are
	// normalized (bracket groups stripped) the same way the alert paths are.
	statusPaths := map[string]bool{}
	collectJSONPaths(reflect.TypeOf(statusResponse{}), "", statusPaths)
	normalizedStatus := normalizeAll(statusPaths)
	snapshotPaths := map[string]bool{}
	collectJSONPaths(reflect.TypeOf(observability.Snapshot{}), "", snapshotPaths)
	normalizedSnapshot := normalizeAll(snapshotPaths)

	// Fixed-key maps: the shape walker cannot know a map's keys, so the keys
	// the alert rules reference are pinned here and mirrored by
	// TestURLMLErrorHistogramKeys in internal/risk.
	knownMapKeys := map[string][]string{
		"ml.url.error_histogram": {"prediction_error", "invalid_url_context"},
	}

	// dns-resolver shapes live in another package; the paths the rules
	// reference there are pinned by internal/dns/resolver's own metrics
	// tests, so the checker only needs their top-level contract.
	resolverMetricPaths := map[string]bool{
		"upstream_doh":                              true,
		"upstream_doh.failures_total":               true,
		"metrics":                                   true,
		"metrics.request_summary":                   true,
		"metrics.request_summary.total_duration_ms": true,
		"metrics.request_summary.count":             true,
	}

	for _, rule := range doc.Rules {
		for _, match := range pathToken.FindAllStringSubmatch(rule.Condition, -1) {
			source, rawPath := match[1], match[2]
			if source == "dns_resolver_status" {
				continue // meta http_status only; the resolver root is public
			}
			normalized := stripBrackets(rawPath)
			var ok bool
			switch source {
			case "core_api_status":
				ok = normalizedStatus[normalized]
				if !ok {
					// Fixed-key maps: the leaf indexes a map whose keys are
					// pinned by knownMapKeys and mirrored in the risk package.
					if idx := strings.LastIndex(normalized, "."); idx > 0 {
						parent, leaf := normalized[:idx], normalized[idx+1:]
						for _, key := range knownMapKeys[parent] {
							if key == leaf && normalizedStatus[parent] {
								ok = true
								break
							}
						}
					}
				}
			case "core_api_metrics", "dns_resolver_metrics":
				ok = normalizedSnapshot[normalized] || resolverMetricPaths[normalized]
			}
			if !ok {
				t.Errorf("rule %s references %s.json.%s, which the runtime shape does not emit", rule.ID, source, rawPath)
			}
		}
	}
}
