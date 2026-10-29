package analysis

import "testing"

func TestEnglishBigramRatio(t *testing.T) {
	cases := []struct {
		label string
		min   float64
		max   float64
	}{
		// Legitimate brandable names: high character spread, English-like pairs.
		{"zoom", 0.5, 1.0},
		{"flickr", 0.4, 1.0},
		{"google", 0.3, 1.0},
		{"facebook", 0.3, 1.0},
		{"shopify", 0.3, 1.0},
		// Classic algorithmic labels: no English letter pairs at all.
		{"qxzvjkwrmp", 0.0, 0.1},
		{"bxwqzkvjht", 0.0, 0.1},
		{"x7z9q2v4jk", 0.0, 0.1},
	}
	for _, tc := range cases {
		got := englishBigramRatio(tc.label)
		if got < tc.min || got > tc.max {
			t.Errorf("englishBigramRatio(%q) = %.2f, want in [%.2f, %.2f]", tc.label, got, tc.min, tc.max)
		}
	}
}

func TestEnglishBigramRatioDegenerate(t *testing.T) {
	if got := englishBigramRatio(""); got != 1 {
		t.Fatalf("empty label should score 1, got %v", got)
	}
	if got := englishBigramRatio("abc123"); got < 1.0/6.0 {
		// "abc" contributes ab, bc; three digit boundaries are irregular.
		t.Fatalf("digit-heavy label should score low, got %v", got)
	}
}

func TestIsDGASuspected(t *testing.T) {
	const threshold = 3.0
	// High entropy + irregular pairs: the classic DGA shape.
	if !isDGASuspected("qxzvjkwrmp", threshold) {
		t.Fatal("high-entropy irregular label should be suspected")
	}
	// High entropy but English-like pairs: legitimate brandable name.
	if isDGASuspected("strawberry", threshold) {
		t.Fatal("English-like high-spread label should not be suspected")
	}
	// Below the soft band: never suspected.
	if isDGASuspected("clearmoney", threshold) {
		t.Fatal("low-entropy label should not be suspected")
	}
	// Short labels are out of scope for the lexical DGA gate.
	if isDGASuspected("qxzvj", threshold) {
		t.Fatal("short labels are guarded by the caller, not here")
	}
}

func BenchmarkEnglishBigramRatio(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = englishBigramRatio("qxzvjkwrmp")
	}
}
