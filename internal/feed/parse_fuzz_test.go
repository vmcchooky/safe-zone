package feed

import (
	"strings"
	"testing"
)

// FuzzParseEachIndicator feeds arbitrary bytes through the threat-feed front
// door (text/CSV sniffing, normalization, dedup). Feed content is fully
// untrusted operator input, so the parser must never panic or hang, and the
// same input must always produce the same admission sequence.
func FuzzParseEachIndicator(f *testing.F) {
	seeds := []string{
		"example.com\nphishing.test\n",
		"http://evil.example.com/login?x=1\nhttps://good.example.org/\n",
		"domain,category\nbad.example.net,phishing\n",
		"||ads.example.com^\n@@||allow.example.com^\n",
		"\x00\xff\xfe invalid \n..,,..\n*.wildcard.example.com\n",
		"a." + strings.Repeat("b", 300) + ".com\n",
		"\"quoted,domain.example.com\",malicious\n",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	collect := func(input string) ([]string, string) {
		var out []string
		stats := &ParseStats{}
		err := ParseEachIndicator(strings.NewReader(input), func(ind Indicator, _ bool) error {
			out = append(out, ind.Domain+"|"+string(ind.Kind))
			return nil
		}, stats)
		errStr := ""
		if err != nil {
			errStr = err.Error()
		}
		return out, errStr
	}
	f.Fuzz(func(t *testing.T, input string) {
		first, firstErr := collect(input)
		second, secondErr := collect(input)
		if firstErr != secondErr {
			t.Fatalf("ParseEachIndicator(%q) nondeterministic error: %q vs %q", input, firstErr, secondErr)
		}
		if len(first) != len(second) {
			t.Fatalf("ParseEachIndicator(%q) nondeterministic output length: %d vs %d", input, len(first), len(second))
		}
		for i := range first {
			if first[i] != second[i] {
				t.Fatalf("ParseEachIndicator(%q) nondeterministic output at %d: %q vs %q", input, i, first[i], second[i])
			}
		}
	})
}
