package risk

import (
	"fmt"
	"testing"
)

func TestBloomFilterBasic(t *testing.T) {
	bf := NewBloomFilter(1000, 0.01)

	// Verify configuration
	m, k := bf.Info()
	if m == 0 || k == 0 {
		t.Fatalf("expected positive bits and hashes, got m=%d, k=%d", m, k)
	}

	elements := []string{"google.com", "facebook.com", "github.com", "amazon.com"}

	// Initially, none should be present
	for _, el := range elements {
		if bf.Test(el) {
			t.Errorf("expected %s to not be found initially", el)
		}
	}

	// Add elements
	for _, el := range elements {
		bf.Add(el)
	}

	// Now all should be present (definitely true)
	for _, el := range elements {
		if !bf.Test(el) {
			t.Errorf("expected %s to be found after adding", el)
		}
	}

	// Test negative cases
	negatives := []string{"evil.com", "scam.xyz", "attacker.net"}
	for _, el := range negatives {
		// With only 4 elements added, false positive probability is virtually 0
		if bf.Test(el) {
			t.Errorf("unexpected false positive for %s", el)
		}
	}
}

func TestBloomFilterFalsePositiveRate(t *testing.T) {
	n := 10000
	p := 0.01 // 1%
	bf := NewBloomFilter(n, p)

	// Insert n unique elements
	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("domain-%d.com", i))
	}

	// Verify all inserted elements are found (No false negatives)
	for i := 0; i < n; i++ {
		el := fmt.Sprintf("domain-%d.com", i)
		if !bf.Test(el) {
			t.Fatalf("false negative found for %s", el)
		}
	}

	// Test another n elements that were not inserted to count false positives
	falsePositives := 0
	testCount := 10000
	for i := 0; i < testCount; i++ {
		el := fmt.Sprintf("not-present-%d.com", i)
		if bf.Test(el) {
			falsePositives++
		}
	}

	fpRate := float64(falsePositives) / float64(testCount)
	t.Logf("Theoretical false positive rate: %f", p)
	t.Logf("Empirical false positive rate: %f (%d/%d)", fpRate, falsePositives, testCount)

	// Empirical rate should be close to theoretical rate (e.g. less than 1.5% for p = 1%)
	if fpRate > p*1.5 {
		t.Errorf("empirical false positive rate %f too high (expected <= %f)", fpRate, p*1.5)
	}
}

func TestBloomFilterEdgeCases(t *testing.T) {
	// Nil filter shouldn't panic
	var nilBF *BloomFilter
	nilBF.Add("test.com")
	if nilBF.Test("test.com") {
		t.Fatal("nil filter should not match")
	}

	// Out of bound / extreme configs
	bf1 := NewBloomFilter(-5, -0.1)
	if bf1 == nil {
		t.Fatal("expected fallback to work")
	}

	bf2 := NewBloomFilter(0, 1.5)
	if bf2 == nil {
		t.Fatal("expected fallback to work")
	}
}
