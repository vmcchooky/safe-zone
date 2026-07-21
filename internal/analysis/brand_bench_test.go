package analysis

import "testing"

func BenchmarkLevenshteinDistance(b *testing.B) {
	s1 := "google"
	s2 := "go0g1e"
	for b.Loop() {
		LevenshteinDistance(s1, s2)
	}
}

func BenchmarkWeightedLevenshteinDistance(b *testing.B) {
	s1 := "facebook"
	s2 := "faceb0ok"
	for b.Loop() {
		WeightedLevenshteinDistance(s1, s2)
	}
}

func BenchmarkToSkeleton(b *testing.B) {
	s := "аpple" // 'a' is cyrillic
	for b.Loop() {
		ToSkeleton(s)
	}
}
