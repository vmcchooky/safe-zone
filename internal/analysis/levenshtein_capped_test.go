package analysis

import (
	"math"
	"math/rand"
	"testing"
)

// Capped variants must agree with the full versions on every input:
// exact value at or below the cap, strictly above it otherwise.
func TestLevenshteinCappedEquivalent(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	alpha := []rune("abcdefghijklmnopqrstuvwxyz0123456789-")
	mk := func() string {
		n := rng.Intn(14)
		r := make([]rune, n)
		for i := range r {
			r[i] = alpha[rng.Intn(len(alpha))]
		}
		return string(r)
	}
	brands := []string{"google", "paypal", "momo", "tiki", "vietcombank", "shopee", "microsoft", "a"}
	for i := 0; i < 4000; i++ {
		a, b := mk(), brands[rng.Intn(len(brands))]
		full := LevenshteinDistance(a, b)
		for _, cap := range []int{1, 2} {
			got := LevenshteinDistanceCapped(a, b, cap)
			if full <= cap && got != full {
				t.Fatalf("(%q,%q) cap %d: got %d, want exact %d", a, b, cap, got, full)
			}
			if full > cap && got <= cap {
				t.Fatalf("(%q,%q) cap %d: got %d, want > %d (full %d)", a, b, cap, got, cap, full)
			}
		}
		wfull := WeightedLevenshteinDistance(a, b)
		for _, cap := range []float64{1.0, 1.5} {
			got := WeightedLevenshteinDistanceCapped(a, b, cap)
			if wfull <= cap && math.Abs(got-wfull) > 1e-9 {
				t.Fatalf("w(%q,%q) cap %v: got %v, want exact %v", a, b, cap, got, wfull)
			}
			if wfull > cap && !(got > cap) {
				t.Fatalf("w(%q,%q) cap %v: got %v, want > cap (full %v)", a, b, cap, got, wfull)
			}
		}
	}
}
