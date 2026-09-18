package risk

import (
	"strings"
	"testing"

	"safe-zone/internal/domaintrie"
)

// Section categories come from each block's own documented purpose; blocks
// without one keep the source-level category instead of guessing.
func TestParseAdblockSourceSectionCategories(t *testing.T) {
	service := NewService(Options{})
	defer func() { _ = service.Close() }()

	body := `# No section yet: source-level category applies.
0.0.0.0 plain.example.com
# Start adaway.org
0.0.0.0 tracked.example.com
# Start hostsVN
0.0.0.0 Quang-cao.example.com
# Start some-unknown-block
0.0.0.0 mystery.example.com
# Start your engines prose must not flip sections
0.0.0.0 still-mystery.example.com
# End
0.0.0.0 after-end.example.com
`
	trie := domaintrie.NewTrie()
	if err := service.parseAdblockSource(strings.NewReader(body), trie, "src",
		domaintrie.DefaultRuleCategory, domaintrie.RuleScopeSuffix, domaintrie.OriginGlobalDefault); err != nil {
		t.Fatal(err)
	}

	cases := map[string]string{
		"plain.example.com":         "unknown",
		"tracked.example.com":       "tracking",
		"quang-cao.example.com":     "ads",
		"mystery.example.com":       "unknown",
		"still-mystery.example.com": "unknown",
		"after-end.example.com":     "unknown",
	}
	for domain, want := range cases {
		detail := trie.MatchRuleDetail(domain)
		if !detail.Matched {
			t.Fatalf("expected %s to match", domain)
		}
		if detail.Rule.Category != want {
			t.Errorf("%s category = %q; want %q", domain, detail.Rule.Category, want)
		}
	}
}

func TestParseAdblockSectionMarkerShapes(t *testing.T) {
	if name, end := parseAdblockSectionMarker("# Start adaway.org"); name != "adaway.org" || end {
		t.Fatalf("start marker = %q/%v", name, end)
	}
	if _, end := parseAdblockSectionMarker("# End"); !end {
		t.Fatal("end marker must clear")
	}
	if _, end := parseAdblockSectionMarker("#End"); !end {
		t.Fatal("compact end marker must clear")
	}
	// Prose and inline comments never flip section state.
	for _, line := range []string{
		"# Start your engines",
		"# Start",
		"# Just a comment",
		"0.0.0.0 host.example.com # trailing comment",
		"",
	} {
		if name, end := parseAdblockSectionMarker(line); name != "" || end {
			t.Fatalf("line %q must not parse as marker", line)
		}
	}
}
